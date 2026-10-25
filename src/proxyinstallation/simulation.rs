use crate::domain::Phase;

/// Explicit fixture facts, never observations of the machine running the demo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    pub root: bool,
    pub ubuntu_24_04: bool,
    pub amd64: bool,
    pub owned_paths_absent: bool,
    pub port_443_available: bool,
    pub mutation_idle: bool,
    pub destination_compatible: bool,
}

impl Facts {
    pub fn refusal(self, phase: Phase) -> Option<&'static str> {
        if !self.root || !self.ubuntu_24_04 || !self.amd64 {
            Some("Setup requires root authority on Ubuntu Server 24.04 amd64.")
        } else if !self.mutation_idle {
            Some("Another mutation is active. Retry after it completes.")
        } else if phase == Phase::Absent && !self.owned_paths_absent {
            Some("Existing or unknown ownership/resources refuse clean installation.")
        } else if !self.port_443_available || !self.destination_compatible {
            Some("Port or destination safety facts cannot be verified.")
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationFault {
    BeforeActivation,
    AfterActivation,
}

pub struct SimulatedHost {
    pub facts: Facts,
    pub fault: Option<SimulationFault>,
    pub effects: u64,
    pub(super) phase: Phase,
}

impl Default for SimulatedHost {
    fn default() -> Self {
        Self {
            facts: Facts {
                root: true,
                ubuntu_24_04: true,
                amd64: true,
                owned_paths_absent: true,
                port_443_available: true,
                mutation_idle: true,
                destination_compatible: true,
            },
            fault: None,
            effects: 0,
            phase: Phase::Absent,
        }
    }
}

impl SimulatedHost {
    pub(super) fn transition(&mut self, phase: Phase) {
        self.phase = phase;
        self.effects += 1;
    }
}
