extern crate proc_macro;
extern crate syn;

use syn::{Attribute, braced, bracketed, Item, ItemStruct};
use syn::parse::{Parse, ParseStream};
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
pub fn packet(input: TokenStream, attr: TokenStream) -> TokenStream {
    input
}

#[proc_macro]
pub fn packets(input: TokenStream) -> proc_macro::TokenStream {
    println!("Called packets: {:?}", input);
    let packets = syn::parse::<Packets>(input.clone()).expect("Packets parse failed");
    println!("Content: {:?}", packets.items);

    let mut macro_out = Vec::new();
    for packet in packets.items {
        let expanded = expand_packet(packet);
        macro_out.push(quote! { #expanded });
    }
    //let item: Vec<syn::Item> = syn::parse(input.clone()).unwrap();
    //println!("Item: {:?}", item);
    TokenStream::from(quote! {
        #(#macro_out)*
    })
}

//#[proc_macro_attribute]
fn expand_packet(mut user_struct: syn::ItemStruct) -> proc_macro2::TokenStream {

    println!("Struct: {:?}", user_struct);
    //let user_struct: syn::ItemStruct = syn::parse(item.clone()).unwrap();

    //let args: proc_macro2::TokenStream = attr.into();
    //let full_attr = quote!(#[packet(#args)]);

    //let attrs = syn::parse2::<DummyParse>(full_attr).expect("syn::parse failed").attrs;
    //let attrs = user_struct.attrs;

    // Partially taken from
    // https://github.com/SergioBenitez/Rocket/blob/50567058841ca2b1cea265a779fa882438da0bad/core/codegen/src/lib.rs
    //

    let Packet = quote!(crate::packet::Packet);
    let PacketState = quote!(crate::packet::PacketState);
    let Side = quote!(crate::packet::Side);

    let mut packet_id = None;
    let mut packet_state = None;
    let mut packet_side = None;

    //println!("Item: {:?}", user_struct);

    //let function: syn::ItemStruct = syn::parse(item).expect("Failed to parse struct");
    //let function = user_struct;
    let name = user_struct.ident.clone();

    user_struct.attrs.retain(|attr| {
        println!("Attr: {:?}", attr.path);
        let meta = attr.parse_meta().expect("Failed to parse meta");
        println!("Meta: {:?}", meta);

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
        return false;
    });

    println!("Got: {:?} {:?} {:?}", packet_id, packet_state, packet_side);

    let packet_id = packet_id.expect("Packet id not found!");
    let packet_state = packet_state.expect("Packet state not found!");
    let packet_side = packet_side.expect("Packet side not found!");

    let mut write_vars = Vec::new();
    let mut read_vars = Vec::new();

    for field in user_struct.fields.iter() {
        println!("Ty: {:?}", field.ty);
        let ident = field.ident.as_ref().unwrap();
        write_vars.push(quote! { self.#ident.write(w); } );
        read_vars.push(quote! { self.#ident.read(r); } );
    }


    let gen = quote! {

        #[derive(Default, Clone)]
        #user_struct

        impl Packet for #name {
            /*const ID: u64 = #packet_id;
            const STATE: PacketState = #packet_state;
            const SIDE: Side = #packet_side;*/
        }

        impl crate::packet::Writeable for #name {
            fn write<W: ::std::io::Write>(&self, w: &mut W) {
                //let p: Box<Packet> = Box::new(self);
                #(#write_vars)*
            }
        }

        impl crate::packet::Readable for #name {
            fn read<R: ::std::io::Read>(&mut self, r: &mut R) {
                //let p: Box<Packet> = Box::new(self);
                #(#read_vars)*
            }
        }
    };

    gen.into()
}
