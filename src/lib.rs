#[cfg(target_family = "unix")]
use termios::{cfmakeraw, tcsetattr, Termios, TCSANOW};

use std::env;
use std::fs::read_to_string;
use std::io;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process;
use std::thread;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, io::Error>;

#[macro_export]
macro_rules! esc {
    ($($arg:expr),*) => { concat!("\x1B", $($arg),*) };
}

#[derive(Debug)]
enum ConnType {
    Local,
    Serial,
    Telnet(i64),
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct UserInfo {
    typ: ConnType,
    pub bbsid: String,
    pub record: i32,
    pub realname: String,
    pub alias: String,
    pub seclevel: i32,
    pub timeleft: u64,
    pub emulation: i32,
    pub node: i32,
    timeout: Instant,
    starttime: Instant,
}

pub trait Conn {
    fn write(&mut self, data: &[u8]) -> Result<()>;

    fn write_str(&mut self, s: &str) -> Result<()> {
        self.write(s.as_bytes())
    }

    fn write_ln(&mut self, line: &str) -> Result<()> {
        self.write_str(line)?;
        self.write_str("\r\n")
    }

    fn read_byte(&mut self) -> Result<u8>;

    fn info(&self) -> &UserInfo;
}

struct LocalUser {
    info: UserInfo,
    #[cfg(target_family = "unix")]
    termios: Termios,
}

impl LocalUser {
    fn new(info: UserInfo) -> LocalUser {
        #[cfg(target_family = "unix")]
        {
            let termios = Termios::from_fd(0).expect("terminal mode");
            let mut raw = termios;
            cfmakeraw(&mut raw);
            tcsetattr(0, TCSANOW, &raw).expect("terminal raw mode");
            LocalUser { info, termios }
        }
        #[cfg(target_family = "windows")]
        LocalUser { info }
    }
}

impl Conn for LocalUser {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        #[cfg(target_family = "unix")]
        {
            io::stdout().write_all(data)?;
            io::stdout().flush()
        }
        #[cfg(target_family = "windows")]
        Ok(())
    }

    fn read_byte(&mut self) -> Result<u8> {
        let mut byte = 0u8;
        #[cfg(target_family = "unix")]
        {
            io::stdin()
                .lock()
                .read_exact(std::slice::from_mut(&mut byte))?;
        }
        Ok(byte)
    }

    fn info(&self) -> &UserInfo {
        &self.info
    }
}

impl Drop for LocalUser {
    fn drop(&mut self) {
        #[cfg(target_family = "unix")]
        tcsetattr(0, TCSANOW, &self.termios).expect("reset terminal");
    }
}

#[derive(Debug)]
struct NetUser {
    info: UserInfo,
    stream: TcpStream,
}

impl NetUser {
    fn read1(&mut self) -> Result<u8> {
        let mut rx_byte: u8 = 0;
        loop {
            match self.stream.read(std::slice::from_mut(&mut rx_byte)) {
                Ok(_) => {
                    self.info.timeout = Instant::now();
                    return Ok(rx_byte);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.maybe_timeout();
                    self.maybe_out_of_time();
                    thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn maybe_timeout(&mut self) {
        const TIME_OUT: u64 = 300;
        if self.info.timeout.elapsed().as_secs() >= TIME_OUT {
            let e = esc!("[1;31m");
            let r = esc!("[0m");
            self.write_ln(format!("\r\n\r\n{e}Timeout!{r}").as_str())
                .expect("write");
            process::exit(0);
        }
    }

    fn maybe_out_of_time(&mut self) {
        let start_time = self.info.starttime;
        let time_left = self.info.timeleft;
        if start_time.elapsed().as_secs() >= time_left {
            let e = esc!("[1;31m");
            let r = esc!("[0m");
            self.write_ln(format!("\r\n\r\n{e}You're out of time!{r}\r\n").as_str())
                .expect("write");
            process::exit(0);
        }
    }
}

impl Conn for NetUser {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.stream.write_all(data)?;
        Ok(())
    }

    fn read_byte(&mut self) -> Result<u8> {
        let mut state = 0;
        loop {
            let rx_byte = self.read1()?;
            state = match (state, rx_byte) {
                (0, 255) => 1,
                (0, _) => return Ok(rx_byte),
                (1, 255) => {
                    self.stream.write_all(std::slice::from_ref(&rx_byte))?;
                    0
                }
                (1, 250) => 3,
                (1, _) => 2,
                (2, _) => 0,
                (3, 240) => 0,
                _ => state,
            };
        }
    }

    fn info(&self) -> &UserInfo {
        &self.info
    }
}

pub struct User {
    typ: bool,
    netuser: Option<NetUser>,
    localuser: Option<LocalUser>,
}

impl Conn for User {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        match self.typ {
            true => {
                self.netuser.as_mut().unwrap().write(data)?;
                return Ok(());
            }
            false => {
                self.localuser.as_mut().unwrap().write(data)?;
                return Ok(());
            }
        };
    }

    fn read_byte(&mut self) -> Result<u8> {
        match self.typ {
            true => return self.netuser.as_mut().unwrap().read_byte(),
            false => return self.localuser.as_mut().unwrap().read_byte(),
        };
    }

    fn info(&self) -> &UserInfo {
        match self.typ {
            true => return &self.netuser.as_ref().unwrap().info,
            false => return &self.localuser.as_ref().unwrap().info,
        };
    }
}

pub fn door_clear_screen(user: &mut User) -> Result<()> {
    user.write_str(
        format!("{}{}", esc!("[2J"), esc!("[1;1H"))
            .to_string()
            .as_str(),
    )
}

pub fn door_display_file(user: &mut User, path: &str) -> Result<()> {
    if let Ok(file) = std::fs::read(path) {
        user.write(&file)?;
        user.write_str(esc!("[0m").to_string().as_str())?;
    }
    Ok(())
}

pub fn door_read_string(user: &mut impl Conn, len: usize) -> Result<String> {
    const BACKSPACE: [u8; 3] = *b"\x08\x20\x08";

    user.write_str(esc!("[s"))?;
    user.write_str(esc!("[1;37;45m"))?;
    for _i in 1..len {
        user.write_str(" ")?;
    }
    user.write_str(esc!("[u"))?;

    let mut received: Vec<u8> = vec![];
    while received.len() != len {
        let ch = user.read_byte()?;
        match ch {
            0 | 10 => {}
            13 => break,
            127 | 8 => {
                if !received.is_empty() {
                    user.write(&BACKSPACE)?;
                    received.truncate(received.len() - 1);
                }
            }
            _ => {
                user.write(std::slice::from_ref(&ch))?;
                received.extend_from_slice(&[ch]);
            }
        }
    }
    let s = std::str::from_utf8(&received).unwrap().to_string();
    user.write_ln(esc!("[0m").to_string().as_str())?;
    Ok(s)
}

fn read_lines(filename: &str) -> Result<Vec<String>> {
    let s = read_to_string(filename)?;
    Ok(s.lines().map(str::to_owned).collect())
}

fn read_trimmed_lines(path: &str) -> Result<Vec<String>> {
    let lines = read_lines(path)?;
    Ok(lines.into_iter().map(|s| s.trim().to_owned()).collect())
}

fn read_door32(path: &str) -> Result<UserInfo> {
    let lines = read_trimmed_lines(path)?;
    let typ = match lines[0].parse::<i32>().expect("i32") {
        0 => ConnType::Local,
        1 => ConnType::Serial,
        2 => ConnType::Telnet(lines[1].parse().expect("door32.sys socket")),
        _ => ConnType::Local,
    };
    let info = UserInfo {
        typ,
        bbsid: lines[3].clone(),
        record: lines[4].parse().expect("door32.sys record"),
        realname: lines[5].clone(),
        alias: lines[6].clone(),
        seclevel: lines[7].parse().expect("door32.sys seclevel"),
        timeleft: lines[8].parse().expect("door32.sys timeleft"),
        emulation: lines[9].parse().expect("door32.sys emulation"),
        node: lines[10].parse().expect("door32.sys node"),
        timeout: Instant::now(),
        starttime: Instant::now(),
    };
    Ok(info)
}

fn convert_socket(sock: i64) -> Result<TcpStream> {
    #[cfg(target_family = "unix")]
    let stream = unsafe {
        use std::os::fd::FromRawFd;
        TcpStream::from_raw_fd(sock as i32)
    };
    #[cfg(target_family = "windows")]
    let stream = unsafe {
        use std::os::windows::io::FromRawSocket;
        drop(std::net::TcpListener::bind("255.255.255.255:0")); // hack to get WSAStartup to fire
        TcpStream::from_raw_socket(sock as u64)
    };
    stream.set_nonblocking(true)?;
    Ok(stream)
}

pub fn door_init() -> Result<User> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() < 2 || 3 < args.len() {
        panic!("Usage: door.exe door32.sys [socket]");
    }
    let mut info = read_door32(&args[1]).expect("read door32.sys");
    let fd = if args.len() == 3 {
        let fd = args[2].parse().expect("Socket is an integer");
        if fd > 0 {
            info.typ = ConnType::Telnet(fd);
            fd
        } else if let ConnType::Telnet(fd) = info.typ {
            fd
        } else {
            0
        }
    } else {
        if let ConnType::Telnet(fd) = info.typ {
            fd
        } else {
            0
        }
    };
    match info.typ {
        ConnType::Serial => panic!("UART not supported"),
        ConnType::Local => {
            let user = LocalUser::new(info);

            let u = User {
                typ: false,
                netuser: None,
                localuser: Some(user),
            };
            return Ok(u);
        }
        ConnType::Telnet(_) => {
            let stream = convert_socket(fd).expect("tcp stream");
            let user = NetUser { info, stream };
            let u = User {
                typ: true,
                netuser: Some(user),
                localuser: None,
            };
            return Ok(u);
        }
    };
}
