extern crate proc_macro;
extern crate syn;

use syn::Attribute;
use quote::{quote};
use proc_macro::TokenStream;

/*pub trait Packet {}

pub enum PacketState {
    Login,
    Play
}

pub enum Side {
    Client,
    Server
}*/

struct DummyParse {
    attrs: Vec<Attribute>
}

impl syn::parse::Parse for DummyParse {
    fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
        Ok(DummyParse {
            attrs: Attribute::parse_outer(input)?
        })
    }
}

#[proc_macro_attribute]
pub fn packet(attr: TokenStream, item: TokenStream) -> TokenStream {

    let user_struct: syn::ItemStruct = syn::parse(item.clone()).unwrap();

    let args: proc_macro2::TokenStream = attr.into();
    let full_attr = quote!(#[packet(#args)]);

    let attrs = syn::parse2::<DummyParse>(full_attr).expect("syn::parse failed").attrs;

    // Partially taken from
    // https://github.com/SergioBenitez/Rocket/blob/50567058841ca2b1cea265a779fa882438da0bad/core/codegen/src/lib.rs
    //

    let Packet = quote!(crate::packet::Packet);
    let PacketState = quote!(crate::packet::PacketState);
    let Side = quote!(crate::packet::Side);

    let mut packet_id = None;
    let mut packet_state = None;
    let mut packet_side = None;

    println!("Item: {:?}", item);

    let function: syn::ItemStruct = syn::parse(item).expect("Failed to parse struct");
    let name = function.ident;

    for attr in &attrs {
        println!("Attr: {:?}", attr.path);
        let meta = attr.parse_meta().expect("Failed to parse meta");
        println!("Meta: {:?}", meta);

        if meta.name() != "packet" {
            continue;
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
                                    "Login" => quote!(#PacketState::Login),
                                    "Play" => quote!(#PacketState::Play),
                                    _ => panic!("Unknown packet state {:?}", lit.value())
                                })
                            } else {
                                panic!("Unexpected state value!");
                            }
                        } else if val.ident.to_string() == "side" {
                            if let syn::Lit::Str(lit) = &val.lit {
                                packet_side = Some(match lit.value().as_str() {
                                    "Client" => quote!(#Side::Client),
                                    "Server" => quote!(#Side::Server),
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
    }

    println!("Got: {:?} {:?} {:?}", packet_id, packet_state, packet_side);

    let packet_id = packet_id.expect("Packet id not found!");
    let packet_state = packet_state.expect("Packet state not found!");
    let packet_side = packet_side.expect("Packet side not found!");

    let gen = quote! {
        #user_struct

        impl Packet for #name {
            const ID: u64 = #packet_id;
            const STATE: PacketState = #packet_state;
            const SIDE: Side = #packet_side;
        }
    };

    gen.into()
}
