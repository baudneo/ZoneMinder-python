from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import Table, Enum, DateTime, Numeric


@dataclass
class ZMConfig:
    Id: int = None
    Name: str = None
    Value: str = None
    Type: str = None
    DefaultValue: str = None
    Hint: str = None
    Pattern: str = None
    Format: str = None
    Prompt: str = None
    Help: str = None
    Category: str = None
    ReadOnly: int = None
    Requires: str = None


@dataclass
class ZMZone:
    """
    ZoneMinder Zones
    """
    Id: int = None
    MonitorId: int = None
    Name: str = None
    Type: Enum = None
    Units: Enum = None
    NumCoords: int = None
    Coords: str = None
    Area: int = None
    AlarmRGB: int = None
    CheckMethod: Enum = None
    MinPixelThreshold: int = None
    MinAlarmPixels: int = None
    MaxPixelThreshold: int = None
    MaxAlarmPixels: int = None
    FilterX: int = None
    FilterY: int = None
    MinFilterPixels: int = None
    MaxFilterPixels: int = None
    MinBlobPixels: int = None
    MaxBlobPixels: int = None
    MaxBlobs: int = None
    MinBlobs: int = None
    OverloadFrames: int = None
    ExtendAlarmFrames: int = None


@dataclass
class ZMState:
    """A dataclass to hold ZoneMinder State information - matches DB Column names."""
    Id: int = None
    Name: str = None
    Definition: str = None
    IsActive: int = None


@dataclass
class ZMMonitor:
    """A dataclass to hold ZoneMinder Monitor information - matches DB Column Names"""
    Id: int = None
    Name: str = None
    Notes: str = None
    ServerId: int = None
    StorageId: int = None
    ManufacturerId: int = None
    ModelId: int = None
    Type: Enum = None
    Function: Enum = None
    Enabled: int = None
    DecodingEnabled: int = None
    LinkedMonitors: str = None
    Triggers: str = None
    EventStartCommand: str = None
    EventEndCommand: str = None
    ONVIF_URL: str = None
    ONVIF_Username: str = None
    ONVIF_Password: str = None
    ONVIF_Options: str = None
    Device: str = None
    Channel: int = None
    Format: int = None
    V4LMultiBuffer: int = None
    V4LCapturePerFrame: int = None
    Protocol: str = None
    Method: str = None
    Host: str = None
    Post: str = None
    SubPath: str = None
    Path: str = None
    SecondPath: str = None
    Options: str = None
    User: str = None
    Pass: str = None
    Width: int = None
    Height: int = None
    Colors: int = None
    Palette: int = None
    Orientation: Enum = None
    Deinterlacing: int = None
    DecoderHWAccelName: str = None
    DecoderHWAccelDevice: str = None
    SaveJPEGs: int = None
    VideoWriter: int = None
    OutputCodec: int = None
    Encoder: str = None
    OutputContainer: Enum = None
    EncoderParameters: str = None
    RecordAudio: int = None
    RTSPDescribe: int = None
    Brightness: int = None
    Contrast: int = None
    Hue: int = None
    Colour: int = None
    EventPrefix: str = None
    LabelFormat: str = None
    LabelX: int = None
    LabelY: int = None
    LabelSize: int = None
    ImageBufferCount: int = None
    MaxImageBufferCount: int = None
    WarmupCount: int = None
    PreEventCount: int = None
    PostEventCount: int = None
    StreamReplayBuffer: int = None
    AlarmFrameCount: int = None
    SectionLength: int = None
    MinSectionLength: int = None
    FrameSkip: int = None
    MotionFrameSkip: int = None
    AnalysisFPSLimit: Numeric = Numeric
    AnalysisUpdateDelay: int = None
    MaxFPS: float = None
    AlarmMaxFPS: float = None
    FPSReportInterval: int = None
    RefBlendPerc: int = None
    AlarmRefBlendPerc: int = None
    Controllable: int = None
    ControlId: int = None
    ControlDevice: str = None
    ControlAddress: str = None
    AutoStopTimeout: float = None
    TrackMotion: int = None
    TrackDelay: int = None
    ReturnLocation: int = None
    ReturnDelay: int = None
    ModectDuringPTZ: int = None
    DefaultRate: int = None
    DefaultScale: int = None
    DefaultCodec: Enum = None
    SignalCheckPoints: int = None
    SignalCheckColour: str = None
    WebColour: str = None
    Exif: int = None
    Sequence: int = None
    ZoneCount: int = None
    Refresh: int = None
    Latitude: float = None
    Longitude: float = None
    RTSPServer: int = None
    RTSPStreamName: str = None
    Importance: Enum = None

    def __len__(self):
        return len(self.__dict__)

    def __iter__(self):
        return iter(self.__dict__.items())


@dataclass
class ZMEvent:
    """A dataclass to hold ZoneMinder Event information - matches DB Column Names"""
    Id: int = None
    MonitorId: int = None
    StorageId: int = None
    SecondaryStorageId: int = None
    Name: str = None
    Cause: str = None
    StartDateTime: DateTime = None
    EndDateTime: DateTime = None
    Width: int = None
    Height: int = None
    Length: float = None
    Frames: int = None
    AlarmFrames: int = None
    DefaultVideo: str = None
    SaveJPEGs: int = None
    TotScore: int = None
    AvgScore: int = None
    MaxScore: int = None
    Archived: int = None
    Videoed: int = None
    Uploaded: int = None
    Emailed: int = None
    Messaged: int = None
    Executed: int = None
    Notes: str = None
    StateId: int = None
    Orientation: Enum = None
    DiskSpace: int = None
    Scheme: Enum = None
    Locked: int = None
    
    
@dataclass
class ZMDB:
    Events: Optional[Table] = field(default_factory=Table)
    Monitors: Optional[Table] = field(default_factory=Table)
    Config: Optional[Table] = field(default_factory=Table)
    ControlPresets: Optional[Table] = field(default_factory=Table)
    Controls: Optional[Table] = field(default_factory=Table)
    Devices: Optional[Table] = field(default_factory=Table)
    Event_Summaries: Optional[Table] = field(default_factory=Table)
    Events_Archived: Optional[Table] = field(default_factory=Table)
    Events_Day: Optional[Table] = field(default_factory=Table)
    Events_Hour: Optional[Table] = field(default_factory=Table)
    Events_Week: Optional[Table] = field(default_factory=Table)
    Events_Month: Optional[Table] = field(default_factory=Table)
    Filters: Optional[Table] = field(default_factory=Table)
    Frames: Optional[Table] = field(default_factory=Table)
    Groups: Optional[Table] = field(default_factory=Table)
    Groups_Monitors: Optional[Table] = field(default_factory=Table)
    Logs: Optional[Table] = field(default_factory=Table)
    Manufacturers: Optional[Table] = field(default_factory=Table)
    Maps: Optional[Table] = field(default_factory=Table)
    Models: Optional[Table] = field(default_factory=Table)
    MonitorPresets: Optional[Table] = field(default_factory=Table)
    Monitor_Status: Optional[Table] = field(default_factory=Table)
    MontageLayouts: Optional[Table] = field(default_factory=Table)
    Servers: Optional[Table] = field(default_factory=Table)
    Sessions: Optional[Table] = field(default_factory=Table)
    Snapshot_Events: Optional[Table] = field(default_factory=Table)
    Snapshots: Optional[Table] = field(default_factory=Table)
    States: Optional[Table] = field(default_factory=Table)
    Stats: Optional[Table] = field(default_factory=Table)
    Storage: Optional[Table] = field(default_factory=Table)
    TriggersX10: Optional[Table] = field(default_factory=Table)
    Users: Optional[Table] = field(default_factory=Table)
    ZonePresets: Optional[Table] = field(default_factory=Table)
    Zones: Optional[Table] = field(default_factory=Table)
