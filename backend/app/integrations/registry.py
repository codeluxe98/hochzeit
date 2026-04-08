from app.integrations.base import IntegrationAdapter


class PlaceholderAdapter(IntegrationAdapter):
    def __init__(self, key: str):
        self.key = key

    def health(self) -> dict:
        return {'key': self.key, 'status': 'placeholder'}

    def overview(self) -> dict:
        return {'key': self.key, 'summary': 'Adapter scaffold ready'}

    def list_items(self) -> list[dict]:
        return []

    def get_item(self, item_id: str) -> dict:
        return {'id': item_id, 'key': self.key}

    def execute_action(self, action: str, payload: dict) -> dict:
        return {'action': action, 'payload': payload, 'status': 'accepted'}


INTEGRATION_KEYS = ['solar', 'ddns', 'wireguard', 'portainer', 'prometheus']


def get_adapter(key: str) -> IntegrationAdapter:
    if key not in INTEGRATION_KEYS:
        raise KeyError(f'Unknown integration: {key}')
    return PlaceholderAdapter(key)
