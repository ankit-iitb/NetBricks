use super::Batch;
use super::act::Act;
use super::iterator::*;
use super::packet_batch::PacketBatch;
use common::*;
use headers::NullHeader;
use interface::PacketTx;

pub struct ResetParsingBatch<V>
where
    V: Batch + BatchIterator + Act,
{
    parent: V,
}

impl<V> ResetParsingBatch<V>
where
    V: Batch + BatchIterator + Act,
{
    pub fn new(parent: V) -> ResetParsingBatch<V> {
        ResetParsingBatch { parent }
    }
}

impl<V> BatchIterator for ResetParsingBatch<V>
where
    V: Batch + BatchIterator + Act,
{
    type Header = NullHeader;
    type Metadata = EmptyMetadata;
    #[inline]
    fn start(&mut self) -> usize {
        self.parent.start()
    }

    #[inline]
    unsafe fn next_payload(&mut self, idx: usize) -> Option<PacketDescriptor<NullHeader, EmptyMetadata>> {
        self.parent.next_payload(idx).map(|PacketDescriptor { packet }| PacketDescriptor {
                packet: packet.reset(),
            })
    }
}

/// Internal interface for packets.
impl<V> Act for ResetParsingBatch<V>
where
    V: Batch + BatchIterator + Act,
{
    act!{}
}

impl<V> Batch for ResetParsingBatch<V>
where
    V: Batch + BatchIterator + Act,
{
}
