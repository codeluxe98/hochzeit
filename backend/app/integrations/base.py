from abc import ABC, abstractmethod


class IntegrationAdapter(ABC):
    key: str

    @abstractmethod
    def health(self) -> dict:
        ...

    @abstractmethod
    def overview(self) -> dict:
        ...

    @abstractmethod
    def list_items(self) -> list[dict]:
        ...

    @abstractmethod
    def get_item(self, item_id: str) -> dict:
        ...

    @abstractmethod
    def execute_action(self, action: str, payload: dict) -> dict:
        ...
