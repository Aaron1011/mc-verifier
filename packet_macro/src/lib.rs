#![recursion_limit="128"]

extern crate proc_macro;
extern crate syn;

use syn::{bracketed, ItemStruct, Ident};
use syn::parse::{Parse, ParseStream};
use quote::{quote};
use proc_macro::TokenStream;
use proc_macro2::Span;

struct Packets {
    items: Vec<ItemStruct>
}

impl Parse for Packets {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let content;
        Ok(Packets {
            items: {
                bracketed!(content in input);
                let mut items = Vec::new();
                while !content.is_empty() {
                    items.push(content.parse()?);
                }
                items
            }
        })
    }
}

#[proc_macro_attribute]
pub fn packet(input: TokenStream, _attr: TokenStream) -> TokenStream {
    input
}

#[proc_macro]
pub fn packets(input: TokenStream) -> proc_macro::TokenStream {
    let packets = syn::parse::<Packets>(input.clone()).expect("Packets parse failed");

    let mut handshake_handlers = Vec::new();
    let mut status_handlers = Vec::new();
    let mut login_handlers = Vec::new();
    let mut play_handlers = Vec::new();


    let mut macro_out = Vec::new();
    for packet in packets.items {
        let packet_data = expand_packet(packet);
        let expanded = packet_data.expanded;
        macro_out.push(quote! { #expanded });

        let handler_id = packet_data.id;
        let name = packet_data.name;
        let handler_fn = quote! {
            Box::new(|mut data: &[u8]| -> crate::packet::ParsedPacket {
                let mut pkt: #name = Default::default();
                let reader: &mut ::std::io::Read = &mut data as &mut ::std::io::Read;
                pkt.read(reader).expect("Failed to parse packet!");
                crate::packet::ParsedPacket {
                    boxed: Box::new(pkt.clone()),
                    any: Box::new(pkt.clone())
                }
            }) as Box<Fn(&[u8]) -> crate::packet::ParsedPacket + Sync>
        };
        let insert_line = quote! {
            map.insert(#handler_id, #handler_fn);
        };

        let handlers = match packet_data.state.as_str() {
            "Handshaking" => &mut handshake_handlers,
            "Status" => &mut status_handlers,
            "Login" => &mut login_handlers,
            "Play" => &mut play_handlers,
            _ => unreachable!() // We'll already have thrown an error
        };
        handlers.push(insert_line);

    }
    //let item: Vec<syn::Item> = syn::parse(input.clone()).unwrap();
    TokenStream::from(quote! {
        use lazy_static::lazy_static;
        lazy_static! {
            pub static ref HANDLERS: [::std::collections::HashMap<u64, Box<Fn(&[u8]) -> ParsedPacket + Sync>>; 4] = {
                [
                    {
                        let mut map = ::std::collections::HashMap::new();
                        #(#handshake_handlers)*
                        map
                    },
                    {
                        let mut map = ::std::collections::HashMap::new();
                        #(#status_handlers)*
                        map
                    },
                    {
                        let mut map = ::std::collections::HashMap::new();
                        #(#login_handlers)*
                        map
                    },
                    {
                        let mut map = ::std::collections::HashMap::new();
                        #(#play_handlers)*
                        map
                    }
                ]
            };
        }
        #(#macro_out)*
    })
}

struct PacketData {
    expanded: proc_macro2::TokenStream,
    name: syn::Ident,
    id: u64,
    state: String,
}

//#[proc_macro_attribute]
fn expand_packet(mut user_struct: syn::ItemStruct) -> PacketData {

    //let user_struct: syn::ItemStruct = syn::parse(item.clone()).unwrap();

    //let args: proc_macro2::TokenStream = attr.into();
    //let full_attr = quote!(#[packet(#args)]);

    //let attrs = syn::parse2::<DummyParse>(full_attr).expect("syn::parse failed").attrs;
    //let attrs = user_struct.attrs;

    // Partially taken from
    // https://github.com/SergioBenitez/Rocket/blob/50567058841ca2b1cea265a779fa882438da0bad/core/codegen/src/lib.rs
    //


    let mut packet_id = None;
    let mut packet_state = None;
    let mut packet_side = None;


    //let function: syn::ItemStruct = syn::parse(item).expect("Failed to parse struct");
    //let function = user_struct;
    let name = user_struct.ident.clone();

    user_struct.attrs.retain(|attr| {
        let meta = attr.parse_meta().expect("Failed to parse meta");

        if meta.name() != "packet" {
            return true;
        }

        if let syn::Meta::List(params) = meta {
            for param in params.nested.iter() {
                match param {
                    syn::NestedMeta::Meta(syn::Meta::NameValue(val)) => {
                        if val.ident.to_string() == "id" {
                            if let syn::Lit::Int(lit) = &val.lit {
                                packet_id = Some(lit.value());
                            } else {
                                panic!("Unexpected id value!");
                            }
                        } else if val.ident.to_string() == "state" {
                            if let syn::Lit::Str(lit) = &val.lit {
                                packet_state = Some(match lit.value().as_str() {
                                    "Handshaking" | "Status" | "Login" | "Play" => lit.value().to_string(),
                                    _ => panic!("Unknown packet state {:?}", lit.value())
                                })
                            } else {
                                panic!("Unexpected state value!");
                            }
                        } else if val.ident.to_string() == "side" {
                            if let syn::Lit::Str(lit) = &val.lit {
                                packet_side = Some(match lit.value().as_str() {
                                    "Client" | "Server" => lit.value().to_string(),
                                    _ => panic!("Unknown packet side {:?}", lit.value())
                                })
                            } else {
                                panic!("Unexpected side value!");
                            }
                        }
                    },
                    _ => panic!("Unexpected param {:?}", param)
                }
            }
        }
        return false;
    });


    let packet_id = packet_id.expect("Packet id not found!");
    let packet_state = packet_state.expect("Packet state not found!");
    let packet_side = packet_side.expect("Packet side not found!");

    let method_name = Ident::new(&format!("on_{}", &name.clone().to_string().to_lowercase()), Span::call_site());

    let invoke = quote! { handler.#method_name(self) };

    //let mut lowername = Ident::new(&format!("handler.on_{}(self)", &name.clone().to_string().to_lowercase()), Span::call_site());
    //let invoke = quote! { #lowername (self); };

    let handler_invoke = match packet_side.as_str() {
        "Client" => quote! { 

            fn handle_client(&self, handler: &mut crate::packet::ClientHandler) -> Box<::std::any::Any> {
                #invoke
            }

            fn handle_server(&self, handler: &mut crate::packet::ServerHandler) -> Box<::std::any::Any> {
                unreachable!()
            }
        },
        "Server" => quote! {

            fn handle_client(&self, handler: &mut crate::packet::ClientHandler) -> Box<::std::any::Any> {
                unreachable!()
            }

            fn handle_server(&self, handler: &mut crate::packet::ServerHandler) -> Box<::std::any::Any> {
                #invoke
            }


        },
        _ => panic!("Unknown side {}", packet_side)
    };

    let mut write_vars = Vec::new();
    let mut read_vars = Vec::new();

    for field in user_struct.fields.iter() {
        let ident = field.ident.as_ref().unwrap();
        write_vars.push(quote! { self.#ident.write(w); } );
        read_vars.push(quote! { self.#ident.read(r)?; } );
    }



    let gen = quote! {

        #[derive(Default, Clone, Debug)]
        #user_struct

        impl Packet for #name {

            fn get_id(&self) -> VarInt {
                VarInt::new(#packet_id)
            }

            #handler_invoke

            /*const ID: u64 = #packet_id;
            const STATE: PacketState = #packet_state;
            const SIDE: Side = #packet_side;*/
        }

        impl crate::packet::Writeable for #name {
            fn write(&self, w: &mut ::std::io::Write) {
                //let p: Box<Packet> = Box::new(self);
                #(#write_vars)*
            }
        }

        impl crate::packet::Readable for #name {
            fn read(&mut self, r: &mut ::std::io::Read) -> crate::packet::ReadResult {
                //let p: Box<Packet> = Box::new(self);
                #(#read_vars)*
                Ok(())
            }
        }
    };

    let expanded = gen.into();

    PacketData {
        expanded,
        name,
        id: packet_id,
        state: packet_state,
    }
}
