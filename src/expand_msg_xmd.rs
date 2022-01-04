use crate::ExpandMsg;
use core::marker::PhantomData;
use digest::{
    core_api::BlockSizeUser,
    generic_array::{typenum::Unsigned, GenericArray},
    Digest,
};
use subtle::{Choice, ConditionallySelectable};

/// Placeholder type for implementing expand_message_xmd based on a hash function
#[derive(Debug)]
pub struct ExpandMsgXmd<HashT> {
    phantom: PhantomData<HashT>,
}

/// ExpandMsgXmd implements expand_message_xmd for the ExpandMsg trait
impl<HashT, const LEN_IN_BYTES: usize> ExpandMsg<LEN_IN_BYTES> for ExpandMsgXmd<HashT>
where
    HashT: Digest + BlockSizeUser,
{
    fn expand_message(msg: &[u8], dst: &[u8]) -> [u8; LEN_IN_BYTES] {
        let b_in_bytes = HashT::OutputSize::to_usize();
        let ell = (LEN_IN_BYTES + b_in_bytes - 1) / b_in_bytes;
        if ell > 255 {
            panic!("ell was too big in expand_message_xmd");
        }
        let b_0 = HashT::new()
            .chain_update(GenericArray::<u8, HashT::BlockSize>::default())
            .chain_update(msg)
            .chain_update([(LEN_IN_BYTES >> 8) as u8, LEN_IN_BYTES as u8, 0u8])
            .chain_update(dst)
            .chain_update([dst.len() as u8])
            .finalize();

        let mut b_vals = HashT::new()
            .chain_update(&b_0[..])
            .chain_update([1u8])
            .chain_update(dst)
            .chain_update([dst.len() as u8])
            .finalize();

        let mut buf = [0u8; LEN_IN_BYTES];
        let mut offset = 0;

        for i in 1..ell {
            // b_0 XOR b_(idx - 1)
            let mut tmp = GenericArray::<u8, HashT::OutputSize>::default();
            b_0.iter()
                .zip(&b_vals[..])
                .enumerate()
                .for_each(|(j, (b0val, bi1val))| tmp[j] = b0val ^ bi1val);
            for b in b_vals {
                buf[offset % LEN_IN_BYTES].conditional_assign(
                    &b,
                    Choice::from(if offset < LEN_IN_BYTES { 1 } else { 0 }),
                );
                offset += 1;
            }
            b_vals = HashT::new()
                .chain_update(tmp)
                .chain_update([(i + 1) as u8])
                .chain_update(dst)
                .chain_update([dst.len() as u8])
                .finalize();
        }
        for b in b_vals {
            buf[offset % LEN_IN_BYTES]
                .conditional_assign(&b, Choice::from(if offset < LEN_IN_BYTES { 1 } else { 0 }));
            offset += 1;
        }
        buf
    }
}
