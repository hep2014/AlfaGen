"""Safe extensions for explicitly labelled identifiers; no arbitrary regex config."""
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator


class FieldRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,47}$")
    labels: list[str] = Field(min_length=1, max_length=16)

    @field_validator("labels")
    @classmethod
    def validate_labels(cls, labels):
        if any(not label.strip() or len(label) > 80 or "\n" in label or "\r" in label for label in labels):
            raise ValueError("invalid_field_label")
        return labels

    def compile(self):
        labels = "|".join(re.escape(label.strip()) for label in self.labels)
        return re.compile(r"(?<!\w)(?:" + labels + r")\s*+[:=]\s*+"
                          r"(?P<value>[A-Za-zА-Яа-яЁё0-9][A-Za-zА-Яа-яЁё0-9_-]{0,63})(?![\w-])", re.IGNORECASE)
