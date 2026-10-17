from typing import Optional
from pydantic import BaseModel, ConfigDict

class MitreTechniqueBase(BaseModel):
    technique_id: str
    name: str
    description: Optional[str] = None
    tactic: str

class MitreTechniqueResponse(MitreTechniqueBase):
    id: int

    model_config = ConfigDict(from_attributes=True)
