use std::cmp;

pub type Key = Vec<u8>;
pub type Value = Vec<u8>;

pub trait Comparer {
    // Compare returns -1, 0, or +1 depending on whether a is 'less than',
    // 'equal to' or 'greater than' b. The two arguments can only be 'equal'
    // if their contents are exactly equal. Furthermore, the empty slice
    // must be 'less than' any non-empty slice.
    fn compare(&self, a: &[u8], b: &[u8]) -> cmp::Ordering;

    // Bellow are advanced functions used to reduce the space requirements
    // for internal data structures such as index blocks.

    // Separator appends a sequence of bytes x to dst such that a <= x && x < b,
    // where 'less than' is consistent with Compare. An implementation should
    // return nil if x equal to a.
    //
    // Either contents of a or b should not by any means modified. Doing so
    // may cause corruption on the internal state.
    fn separator(&self, a: &[u8], b: &[u8]) -> Vec<u8>;

    // Successor appends a sequence of bytes x to dst such that x >= b, where
    // 'less than' is consistent with Compare. An implementation should return
    // nil if x equal to b.
    //
    // Contents of b should not by any means modified. Doing so may cause
    // corruption on the internal state.
    fn successor(&self, b: &[u8]) -> Vec<u8>;
}
