"""Collection layer: network and web asset discovery."""

from .contracts import CollectionBundle, CollectionRequest
from .service import CollectionService

__all__ = [
	"CollectionService",
	"CollectionRequest",
	"CollectionBundle",
]
