"""Base class for all analytics aggregators."""

from abc import ABC, abstractmethod
from uuid import UUID

from sqlalchemy.orm import Session


class BaseAggregator(ABC):
    """Abstract aggregator: queries the DB and returns a typed result.

    All aggregators follow the same interface so they can be consumed
    both by API routes and by the AI Assessor / correlation engine.
    """

    @abstractmethod
    def aggregate(self, db: Session, pcap_id: UUID, **kwargs):
        """Run the aggregation query and return a typed result."""
        ...
