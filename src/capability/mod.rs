#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CapabilityModule;

impl CapabilityModule {
    pub fn name(&self) -> &'static str {
        "capability"
    }
}

#[cfg(test)]
mod tests {
    use super::CapabilityModule;

    #[test]
    fn module_name_is_stable() {
        assert_eq!(CapabilityModule.name(), "capability");
    }
}
