use std::net::SocketAddr;
use std::net::TcpStream;
use ssh2::Session;
use std::io::{BufReader, BufRead, Read};

/// Opens a tunnel to the public internet, exposing the local
/// Minecraft server
trait Tunneler {

    /// Forwards the specified remote address to the specified
    /// local address.
    fn open(&self, local: (&str, u16), remote: (&str, u16)) -> std::io::Result<()>;
}

struct ServeoTunneler {
}

impl Tunneler for ServeoTunneler {
    fn open(&self, local: (&str, u16), remote: (&str, u16)) -> std::io::Result<()> {
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

        loop {
            println!("Accepting!");
            inbound.0.accept();
        }

        Ok(())
    }
}

impl ServeoTunneler {
    fn new() -> ServeoTunneler {
        ServeoTunneler {
        }
    }
}

fn main() {
    //ServeoTunneler::new().open(("localhost", 25567), ("localhost", 4000)).unwrap();
    ServeoTunneler::new().open(("localhost", 25567), ("testing.mc.aaron1011.pw", 25565)).unwrap();
}
