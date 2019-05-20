use std::net::SocketAddr;
//use std::net::TcpStream;
//use ssh2::Session;
//use thrussh::client::Handler;
//use thrussh::server::{Auth, Session};
//use std::io::{BufReader, BufRead, Read};
//use tokio::prelude::Future;
//use std::sync::Arc;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use mc_verifier::server_future;

/// Opens a tunnel to the public internet, exposing the local
/// Minecraft server
trait Tunneler {

    /// Forwards the specified remote address to the specified
    /// local address.
    fn open(&self, forwards: &[PortFoward]) -> Result<(), std::io::Error>;
}

static DBCLIENT_BIN: &'static [u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dbclient"));

struct DropbearTunneler {
    host: String,
    private_key: PathBuf
}

impl DropbearTunneler {

    fn new<P: Into<PathBuf>>(host: &str, private_key: P) -> DropbearTunneler {
        DropbearTunneler {
            host: host.to_string(),
            private_key: private_key.into()
        }
    }

    #[cfg(target_os = "linux")]
    fn fork_in_memory(&self, args: &[String]) -> Result<(), std::io::Error> {
        use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
        use nix::unistd::{fexecve, ForkResult};
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        use std::fs::File;
        use std::io::Write;;

        let args: Vec<CString> = args.iter().map(|s| CString::new(s.clone()).unwrap()).collect();

        let fd = memfd_create(&CString::new("dropbear").unwrap(), MemFdCreateFlag::MFD_CLOEXEC).unwrap();
        let mut file = unsafe { File::from_raw_fd(fd) } ;
        file.write_all(DBCLIENT_BIN)?;
        let fd = file.into_raw_fd();


        match nix::unistd::fork().unwrap() {
            ForkResult::Child => {
                fexecve(fd, &args, &[]).unwrap();
                Ok(())
            },
            ForkResult::Parent { ..} => Ok(())
        }
    }
}

struct PortFoward {
    local: (String, u16),
    remote: (String, u16)
}

impl Tunneler for DropbearTunneler {
    fn open(&self, forwards: &[PortFoward]) -> Result<(), std::io::Error> {
        let mut args = vec!["-i".to_string(), self.private_key.to_str().unwrap().to_string()];
        for forward in forwards {
            args.push("-R".to_string());
            args.push(format!("{}:{}:{}:{}", forward.remote.0, forward.remote.1, forward.local.0, forward.local.1));
        }
        args.push(self.host.clone());
        self.fork_in_memory(&args)
    }
}


/*struct ServeoTunneler;

impl Handler for ServeoTunneler {
    type Error = ();
    type FutureBool = ();
    type FutureUnit = ();
    type FutureSign = ();
    type SessionUnit = ();
}

impl Tunneler for ServeoTunneler {
    fn open(&self, local: (&str, u16), remote: (&str, u16)) -> Box<Future<Item = (), Error = ()>> {
        let mut session = Session::new().unwrap();

        {
            let mut agent = session.agent().unwrap();

            // Connect the agent and request a list of identities
            agent.connect().unwrap();
            agent.list_identities().unwrap();

            for identity in agent.identities() {
                let identity = identity.unwrap(); // assume no I/O errors
                println!("{}", identity.comment());
                let pubkey = identity.blob();
            }
        }

        let tcp = TcpStream::connect("serveo.net:22").unwrap();
        //let tcp = TcpStream::connect("localhost:4000").unwrap();
        session.handshake(&tcp).unwrap();

        session.userauth_agent("aaron");
        session.userauth_keyboard_interactive("aaron", |name, instruction, responses| {
            println!("Challenge: {} {} {:?}", name, instruction, responses)
        }).unwrap();
        assert!(session.authenticated());
        println!("Authenticated!");


        let mut inbound = session.channel_forward_listen(remote.1, /*Some(remote.0)*/None, None).unwrap();
        //session.channel_direct_tcpip("", /*remote.0,*/ remote.1, Some(local)).unwrap();

        let mut channel = session.channel_session().unwrap();
        //let mut s = vec![0; 4];
        let mut s = String::new();

        channel.request_pty("", None, None).unwrap();
        channel.shell().unwrap();

        let mut wrapped = BufReader::new(channel);

        session.set_blocking(false);
        println!("Reading: ");
        loop {
            match wrapped.read_line(&mut s) {
                Ok(len) => {
                    print!("{}", s);
                    s.clear();
                }
                Err(e) => {
                    println!("Error: {:?}", e);
                    break;
                }
            }
        }
        session.set_blocking(true);
        //channel.read_exact(&mut s);

        //BufReader::new(channel).read_line(&mut s).unwrap();
        //println!("Output: {:?}", s);

        std::thread::spawn(|| {
            loop {
                println!("Accepting!");
                match inbound.0.accept() => {
                    Ok(chan) => {
                        let chan = Arc::new(chan);
                        std::thread::spawn(||)
                    }
                }

            }
        })



        Ok(())
    }
}

impl ServeoTunneler {
    fn new() -> ServeoTunneler {
        ServeoTunneler {
        }
    }
}*/

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let domain = args[1].clone();
    let key = args[2].clone();
    DropbearTunneler::new("serveo.net", key).open(&[
        PortFoward {
            local: ("localhost".to_string(), 25565),
            remote: (domain.to_string(), 25568)
        }]).expect("Failed to port forward!");

    let addr = "127.0.0.1:25565".parse::<SocketAddr>().unwrap();
    println!("Running server on {:?}", addr);
    tokio::run(server_future(addr, |addr| {
        println!("Client {:?} disconnected, stopping server", addr);
        true
    }));
    //ServeoTunneler::new().open(("localhost", 25567), ("localhost", 4000)).unwrap();
    //ServeoTunneler::new().open(("localhost", 25567), ("testing.mc.aaron1011.pw", 25565)).unwrap();
}
