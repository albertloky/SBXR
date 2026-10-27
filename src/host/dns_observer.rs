//! Payload-free uprobe seam. No observer is launched or required by the product.
//! Linux observer must select fork on the calling TID between Begin and Spawned,
//! then verify Spawned's PID; Finish is after owned child cleanup. Query IDs come
//! from the existing trace, never from executable names or timing proximity.
use std::cell::Cell;

// C register ABI, deliberately not an exported/unmangled symbol (unsafe forbidden).
// Resolve this exact symbol in the exact unstripped candidate before attachment.
// black_box prevents an empty body/call from being eliminated in release builds.
#[inline(never)]
pub(super) extern "C" fn dns_child_observer_hook(event: u64, query: u64, child: u64) {
    std::hint::black_box((event, query, child));
    #[cfg(test)]
    EVENTS.with(|events| events.borrow_mut().push((event, query, child)));
}

pub(super) struct Scope {
    query: Option<u64>,
    child: Cell<u64>,
}
impl Scope {
    pub(super) fn begin(query: Option<u64>) -> Self {
        if let Some(id) = query {
            dns_child_observer_hook(1, id, 0);
        }
        Self {
            query,
            child: Cell::new(0),
        }
    }
    pub(super) fn spawned(&self, pid: u32) {
        self.child.set(u64::from(pid));
        if let Some(id) = self.query {
            dns_child_observer_hook(2, id, u64::from(pid));
        }
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        if let Some(id) = self.query {
            dns_child_observer_hook(3, id, self.child.get());
        }
    }
}

#[cfg(test)]
thread_local! {
    static EVENTS: std::cell::RefCell<Vec<(u64, u64, u64)>> = const { std::cell::RefCell::new(Vec::new()) };
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_observer_scope_correlates_and_closes_without_processes() {
        EVENTS.with(|e| e.borrow_mut().clear());
        {
            let s = Scope::begin(Some(7));
            s.spawned(123);
        }
        {
            let _s = Scope::begin(Some(8));
        } // spawn refusal
        {
            let s = Scope::begin(None);
            s.spawned(456);
        }
        EVENTS.with(|e| {
            assert_eq!(
                *e.borrow(),
                vec![(1, 7, 0), (2, 7, 123), (3, 7, 123), (1, 8, 0), (3, 8, 0)]
            )
        });
    }
}
