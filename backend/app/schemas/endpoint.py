from app.schemas.common import APIModel


class EndpointItem(APIModel):
    operation_id: str
    method: str
    path: str


class EndpointListResponse(APIModel):
    # TODO: Endpoint search, pagination, and sorting contract pending.
    items: list[EndpointItem]

