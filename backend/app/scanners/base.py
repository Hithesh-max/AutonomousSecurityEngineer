from abc import ABC, abstractmethod

class SecurityScanner(ABC):

    @abstractmethod
    def validate_environment(self):
        pass

    @abstractmethod
    def build_command(self, target, config):
        pass

    @abstractmethod
    def execute(self, target, config):
        pass

    @abstractmethod
    def parse_output(self, output):
        pass

    @abstractmethod
    def normalize_findings(self, parsed):
        pass
