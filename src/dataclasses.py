from dataclasses import dataclass, field, fields
from typing import Optional

from sqlalchemy import Table, Enum, DateTime, Numeric


@dataclass
class ZMGroups:
    Id: int = None
    ParentId: int = None
    Name: str = None


@dataclass(frozen=True)
class InterfacePrivs:
    Stream: str
    Events: str
    Control: str
    Monitors: str
    Groups: str
    Snapshots: str
    System: str
    Devices: str


@dataclass
class ZMServers:
    Id: int = None
    Protocol: str = None
    Hostname: str = None
    Port: int = None
    PathToIndex: str = None
    PathToZMS: str = None
    PathToApi: str = None
    Name: str = None
    StateId: int = None
    Status: Enum = None
    CpuLoad: float = None
    TotalMem: int = None
    FreeSwap: int = None
    zmstats: int = None
    zmaudit: int = None
    zmtrigger: int = None
    zmeventnotification: int = None


@dataclass
class ZMLayouts:
    Id: int = None
    Name: str = None
    Positions: int = None


@dataclass
class ZMUsers:
    Id: int = None
    Username: str = None
    Password: str = None
    Language: str = None
    Enabled: int = None
    Stream: Enum = None
    Events: Enum = None
    Control: Enum = None
    Monitors: Enum = None
    Groups: Enum = None
    Devices: Enum = None
    Snapshots: Enum = None
    System: Enum = None
    MaxBandwidth: str = None
    MonitorIds: str = None
    TokenMinExpiry: int = None
    APIEnabled: int = None
    HomeView: str = None


@dataclass
class ZMGroups:
    Id: int = None



@dataclass
class ZMLogs:
    Id: int = None
    TimeKey: float = None
    Component: str = None
    ServerId: int = None
    Pid: int = None
    Level: int = None
    Code: str = None
    Message: str = None
    File: str = None
    Line: int = None


@dataclass
class ZMStorage:
    Id: int = None
    Path: str = None
    Name: str = None
    Type: Enum = None
    Url: str = None
    DiskSpace: int = None
    Scheme: Enum = None
    ServerId: int = None
    DoDelete: int = None
    Enabled: int = None


@dataclass
class ZMTriggersX10:
    MonitorId: int = None
    Activation: str = None
    AlarmInput: str = None
    AlarmOutput: str = None

@dataclass
class ZMControl:
    Id: int = None
    Name: str = None
    Type: Enum = None
    Protocol: str = None
    CanWake: int = None
    CanSleep: int = None
    CanReset: int = None
    CanReboot: int = None
    CanZoom: int = None
    CanAutoZoom: int = None
    CanZoomAbs: int = None
    CanZoomRel: int = None
    CanZoomCon: int = None
    MinZoomRange: int = None
    MaxZoomRange: int = None
    MinZoomStep: int = None
    MaxZoomStep: int = None
    HasZoomSpeed: int = None
    MinZoomSpeed: int = None
    MaxZoomSpeed: int = None
    CanFocus: int = None
    CanAutoFocus: int = None
    CanFocusAbs: int = None
    CanFocusRel: int = None
    CanFocusCon: int = None
    MinFocusRange: int = None
    MaxFocusRange: int = None
    MinFocusStep: int = None
    MaxFocusStep: int = None
    HasFocusSpeed: int = None
    MinFocusSpeed: int = None
    MaxFocusSpeed: int = None
    CanIris: int = None
    CanAutoIris: int = None
    CanIrisAbs: int = None
    CanIrisRel: int = None
    CanIrisCon: int = None
    MinIrisRange: int = None
    MaxIrisRange: int = None
    MinIrisStep: int = None
    MaxIrisStep: int = None
    HasIrisSpeed: int = None
    MinIrisSpeed: int = None
    MaxIrisSpeed: int = None
    CanGain: int = None
    CanAutoGain: int = None
    CanGainAbs: int = None
    CanGainRel: int = None
    CanGainCon: int = None
    MinGainRange: int = None
    MaxGainRange: int = None
    MinGainStep: int = None
    MaxGainStep: int = None
    HasGainSpeed: int = None
    MinGainSpeed: int = None
    MaxGainSpeed: int = None
    CanWhite: int = None
    CanAutoWhite: int = None
    CanWhiteAbs: int = None
    CanWhiteRel: int = None
    CanWhiteCon: int = None
    MinWhiteRange: int = None
    MaxWhiteRange: int = None
    MinWhiteStep: int = None
    MaxWhiteStep: int = None
    HasWhiteSpeed: int = None
    MinWhiteSpeed: int = None
    MaxWhiteSpeed: int = None
    HasPresets: int = None
    NumPresets: int = None
    HasHomePreset: int = None
    CanSetPresets: int = None
    CanMove: int = None
    CanMoveDiag: int = None
    CanMoveMap: int = None
    CanMoveAbs: int = None
    CanMoveRel: int = None
    CanMoveCon: int = None
    CanPan: int = None
    MinPanRange: int = None
    MaxPanRange: int = None
    MinPanStep: int = None
    MaxPanStep: int = None
    HasPanSpeed: int = None
    MinPanSpeed: int = None
    MaxPanSpeed: int = None
    HasTurboPan: int = None
    TurboPanSpeed: int = None
    CanTilt: int = None
    MinTiltRange: int = None
    MaxTiltRange: int = None
    MinTiltStep: int = None
    MaxTiltStep: int = None
    HasTiltSpeed: int = None
    MinTiltSpeed: int = None
    MaxTiltSpeed: int = None
    HasTurboTilt: int = None
    TurboTiltSpeed: int = None
    CanAutoScan: int = None
    NumScanPaths: int = None


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
class ZMOptions:
    # Config Items
    Id: int = 1
    # ZM_ADD_JPEG_COMMENTS = None
    # ZM_AUDIT_CHECK_INTERVAL = None
    # ZM_AUDIT_MIN_AGE = None
    # ZM_AUTH_HASH_IPS = None
    # ZM_AUTH_HASH_LOGINS = None
    # ZM_AUTH_HASH_SECRET = None
    # ZM_AUTH_HASH_TTL = None
    # ZM_AUTH_RELAY = None
    # ZM_AUTH_TYPE = None
    # ZM_BANDWIDTH_DEFAULT = None
    # ZM_BULK_FRAME_INTERVAL = None
    # ZM_CAPTURES_PER_FRAME = None
    # ZM_CHECK_FOR_UPDATES = None
    # ZM_COLOUR_JPEG_FILES = None
    # ZM_COOKIE_LIFETIME = None
    # ZM_CPU_EXTENSIONS = None
    # ZM_CSP_REPORT_URI = None
    # ZM_CSS_DEFAULT = None
    # ZM_DEFAULT_ASPECT_RATIO = None
    # ZM_DUMP_CORES = None
    # ZM_DYN_CURR_VERSION = None
    # ZM_DYN_DB_VERSION = None
    # ZM_DYN_DONATE_REMINDER_TIME = None
    # ZM_DYN_LAST_CHECK = None
    # ZM_DYN_LAST_VERSION = None
    # ZM_DYN_NEXT_REMINDER = None
    # ZM_DYN_SHOW_DONATE_REMINDER = None
    # ZM_EMAIL_HOST = None
    # ZM_ENABLE_CSRF_MAGIC = None
    # ZM_EVENT_CLOSE_MODE = None
    # ZM_EVENT_IMAGE_DIGITS = None
    # ZM_FAST_IMAGE_BLENDS = None
    # ZM_FEATURES_SNAPSHOTS = None
    # ZM_FFMPEG_FORMATS = None
    # ZM_FFMPEG_INPUT_OPTIONS = None
    # ZM_FFMPEG_OPEN_TIMEOUT = None
    # ZM_FFMPEG_OUTPUT_OPTIONS = None
    # ZM_FILTER_EXECUTE_INTERVAL = None
    # ZM_FILTER_RELOAD_DELAY = None
    # ZM_FONT_FILE_LOCATION = None
    # ZM_FORCED_ALARM_SCORE = None
    # ZM_FROM_EMAIL = None
    # ZM_HOME_ABOUT = None
    # ZM_HOME_CONTENT = None
    # ZM_HOME_URL = None
    # ZM_HTTP_TIMEOUT = None
    # ZM_HTTP_UA = None
    # ZM_HTTP_VERSION = None
    # ZM_JANUS_PATH = None
    # ZM_JANUS_SECRET = None
    # ZM_JPEG_ALARM_FILE_QUALITY = None
    # ZM_JPEG_FILE_QUALITY = None
    # ZM_JPEG_STREAM_QUALITY = None
    # ZM_LANG_DEFAULT = None
    # ZM_LD_PRELOAD = None
    # ZM_LOG_ALARM_ERR_COUNT = None
    # ZM_LOG_ALARM_FAT_COUNT = None
    # ZM_LOG_ALARM_WAR_COUNT = None
    # ZM_LOG_ALERT_ERR_COUNT = None
    # ZM_LOG_ALERT_FAT_COUNT = None
    # ZM_LOG_ALERT_WAR_COUNT = None
    # ZM_LOG_CHECK_PERIOD = None
    # ZM_LOG_DATABASE_LIMIT = None
    # ZM_LOG_DEBUG = None
    # ZM_LOG_DEBUG_FILE = None
    # ZM_LOG_DEBUG_LEVEL = None
    # ZM_LOG_DEBUG_TARGET = None
    # ZM_LOG_FFMPEG = None
    # ZM_LOG_LEVEL_DATABASE = None
    # ZM_LOG_LEVEL_FILE = None
    # ZM_LOG_LEVEL_SYSLOG = None
    # ZM_LOG_LEVEL_WEBLOG = None
    # ZM_MAX_RESTART_DELAY = None
    # ZM_MAX_RTP_PORT = None
    # ZM_MAX_SUSPEND_TIME = None
    # ZM_MESSAGE_ADDRESS = None
    # ZM_MESSAGE_BODY = None
    # ZM_MESSAGE_SUBJECT = None
    # ZM_MIN_RTP_PORT = None
    # ZM_MIN_RTSP_PORT = None
    # ZM_MIN_STREAMING_PORT = None
    # ZM_MPEG_LIVE_FORMAT = None
    # ZM_MPEG_REPLAY_FORMAT = None
    # ZM_MPEG_TIMED_FRAMES = None
    # ZM_NEW_MAIL_MODULES = None
    # ZM_OPT_ADAPTIVE_SKIP = None
    # ZM_OPT_CAMBOZOLA = None
    # ZM_OPT_CONTROL = None
    # ZM_OPT_EMAIL = None
    # ZM_OPT_FAST_DELETE = None
    # ZM_OPT_FFMPEG = None
    # ZM_OPT_GEOLOCATION_ACCESS_TOKEN = None
    # ZM_OPT_GEOLOCATION_TILE_PROVIDER = None
    # ZM_OPT_GOOG_RECAPTCHA_SECRETKEY = None
    # ZM_OPT_GOOG_RECAPTCHA_SITEKEY = None
    # ZM_OPT_MESSAGE = None
    # ZM_OPT_TRIGGERS = None
    # ZM_OPT_UPLOAD = None
    # ZM_OPT_USE_API = None
    # ZM_OPT_USE_AUTH = None
    # ZM_OPT_USE_EVENTNOTIFICATION = None
    # ZM_OPT_USE_GEOLOCATION = None
    # ZM_OPT_USE_GOOG_RECAPTCHA = None
    # ZM_OPT_USE_LEGACY_API_AUTH = None
    # ZM_OPT_X10 = None
    # ZM_PATH_CAMBOZOLA = None
    # ZM_PATH_FFMPEG = None
    # ZM_RAND_STREAM = None
    # ZM_RECORD_DIAG_IMAGES = None
    # ZM_RECORD_DIAG_IMAGES_FIFO = None
    # ZM_RECORD_EVENT_STATS = None
    # ZM_RELOAD_CAMBOZOLA = None
    # ZM_RUN_AUDIT = None
    # ZM_SHM_KEY = None
    # ZM_SHOW_PRIVACY = None
    # ZM_SKIN_DEFAULT = None
    # ZM_SSMTP_MAIL = None
    # ZM_SSMTP_PATH = None
    # ZM_STATS_UPDATE_INTERVAL = None
    # ZM_STRICT_VIDEO_CONFIG = None
    # ZM_SYSTEM_SHUTDOWN = None
    # ZM_TELEMETRY_DATA = None
    # ZM_TELEMETRY_INTERVAL = None
    # ZM_TELEMETRY_LAST_UPLOAD = None
    # ZM_TELEMETRY_SERVER_ENDPOINT = None
    # ZM_TELEMETRY_UUID = None
    # ZM_TIMESTAMP_CODE_CHAR = None
    # ZM_TIMESTAMP_ON_CAPTURE = None
    # ZM_TIMEZONE = None
    # ZM_UPDATE_CHECK_PROXY = None
    # ZM_UPLOAD_ARCH_ANALYSE = None
    # ZM_UPLOAD_ARCH_COMPRESS = None
    # ZM_UPLOAD_ARCH_FORMAT = None
    # ZM_UPLOAD_DEBUG = None
    # ZM_UPLOAD_FTP_PASSIVE = None
    # ZM_UPLOAD_HOST = None
    # ZM_UPLOAD_LOC_DIR = None
    # ZM_UPLOAD_PASS = None
    # ZM_UPLOAD_PORT = None
    # ZM_UPLOAD_PROTOCOL = None
    # ZM_UPLOAD_REM_DIR = None
    # ZM_UPLOAD_STRICT = None
    # ZM_UPLOAD_TIMEOUT = None
    # ZM_UPLOAD_USER = None
    # ZM_URL = None
    # ZM_USE_DEEP_STORAGE = None
    # ZM_USER_SELF_EDIT = None
    # ZM_V4L_MULTI_BUFFER = None
    # ZM_WATCH_CHECK_INTERVAL = None
    # ZM_WATCH_MAX_DELAY = None
    # ZM_WEB_ALARM_SOUND = None
    # ZM_WEB_ANIMATE_THUMBS = None
    # ZM_WEB_COMPACT_MONTAGE = None
    # ZM_WEB_CONSOLE_BANNER = None
    # ZM_WEB_EVENT_DISK_SPACE = None
    # ZM_WEB_EVENT_SORT_FIELD = None
    # ZM_WEB_EVENT_SORT_ORDER = None
    # ZM_WEB_EVENTS_PER_PAGE = None
    # ZM_WEB_FILTER_SOURCE = None
    # ZM_WEB_H_AJAX_TIMEOUT = None
    # ZM_WEB_H_CAN_STREAM = None
    # ZM_WEB_H_DEFAULT_RATE = None
    # ZM_WEB_H_DEFAULT_SCALE = None
    # ZM_WEB_H_EVENTS_VIEW = None
    # ZM_WEB_H_REFRESH_CYCLE = None
    # ZM_WEB_H_REFRESH_EVENTS = None
    # ZM_WEB_H_REFRESH_IMAGE = None
    # ZM_WEB_H_REFRESH_MAIN = None
    # ZM_WEB_H_REFRESH_NAVBAR = None
    # ZM_WEB_H_REFRESH_STATUS = None
    # ZM_WEB_H_SCALE_THUMBS = None
    # ZM_WEB_H_SHOW_PROGRESS = None
    # ZM_WEB_H_STREAM_METHOD = None
    # ZM_WEB_H_VIDEO_BITRATE = None
    # ZM_WEB_H_VIDEO_MAXFPS = None
    # ZM_WEB_ID_ON_CONSOLE = None
    # ZM_WEB_L_AJAX_TIMEOUT = None
    # ZM_WEB_L_CAN_STREAM = None
    # ZM_WEB_L_DEFAULT_RATE = None
    # ZM_WEB_L_DEFAULT_SCALE = None
    # ZM_WEB_L_EVENTS_VIEW = None
    # ZM_WEB_L_REFRESH_CYCLE = None
    # ZM_WEB_L_REFRESH_EVENTS = None
    # ZM_WEB_L_REFRESH_IMAGE = None
    # ZM_WEB_L_REFRESH_MAIN = None
    # ZM_WEB_L_REFRESH_NAVBAR = None
    # ZM_WEB_L_REFRESH_STATUS = None
    # ZM_WEB_L_SCALE_THUMBS = None
    # ZM_WEB_L_SHOW_PROGRESS = None
    # ZM_WEB_L_STREAM_METHOD = None
    # ZM_WEB_L_VIDEO_BITRATE = None
    # ZM_WEB_L_VIDEO_MAXFPS = None
    # ZM_WEB_LIST_THUMB_HEIGHT = None
    # ZM_WEB_LIST_THUMB_WIDTH = None
    # ZM_WEB_LIST_THUMBS = None
    # ZM_WEB_M_AJAX_TIMEOUT = None
    # ZM_WEB_M_CAN_STREAM = None
    # ZM_WEB_M_DEFAULT_RATE = None
    # ZM_WEB_M_DEFAULT_SCALE = None
    # ZM_WEB_M_EVENTS_VIEW = None
    # ZM_WEB_M_REFRESH_CYCLE = None
    # ZM_WEB_M_REFRESH_EVENTS = None
    # ZM_WEB_M_REFRESH_IMAGE = None
    # ZM_WEB_M_REFRESH_MAIN = None
    # ZM_WEB_M_REFRESH_NAVBAR = None
    # ZM_WEB_M_REFRESH_STATUS = None
    # ZM_WEB_M_SCALE_THUMBS = None
    # ZM_WEB_M_SHOW_PROGRESS = None
    # ZM_WEB_M_STREAM_METHOD = None
    # ZM_WEB_M_VIDEO_BITRATE = None
    # ZM_WEB_M_VIDEO_MAXFPS = None
    # ZM_WEB_NAVBAR_TYPE = None
    # ZM_WEB_POPUP_ON_ALARM = None
    # ZM_WEB_RESIZE_CONSOLE = None
    # ZM_WEB_SOUND_ON_ALARM = None
    # ZM_WEB_TITLE = None
    # ZM_WEB_TITLE_PREFIX = None
    # ZM_WEB_USE_OBJECT_TAGS = None
    # ZM_WEB_XFRAME_WARN = None
    # ZM_WEIGHTED_ALARM_CENTRES = None
    # ZM_X10_DB_RELOAD_INTERVAL = None
    # ZM_X10_DEVICE = None
    # ZM_X10_HOUSE_CODE = None


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


@dataclass
class DBOptions:
    sanitize: bool = False
    conf_path: str = None
    host: str = None
    port: int = None
    user: str = None
    password: str = None
    db_name: str = None
    db_driver: str = None
    extras: dict = field(default_factory=dict)
    zmuser: str = None
    zmpassword: str = None


@dataclass
class APIOptions:
    sanitize: bool = False
    host: str = None
    basic_auth: bool = None
    port: int = None
    user: str = None
    password: str = None
    strict_ssl: bool = None
    api_url: str = None
    portal_url: str = None
    extras: dict = field(default_factory=dict)
