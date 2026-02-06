import json
from response_maker import responseMaker
from database.dbcon import dbGetRMeLOG, dbTransRMeLOG, prepareJson

def routeVerifyUser(UserEmail,DeviceInfo):
    data,rows,cols =  dbGetRMeLOG("EXEC [dbo].[fsp_UserVerification] @Email=?,@DeviceInfo=?",UserEmail,DeviceInfo)
    return responseMaker(prepareJson(rows, cols), "success", 200, "UserVerification")

def routeCrewFlights(RM_UserId,SubmissionId,LastDays,NextDays):  
    data,rows,cols =  dbGetRMeLOG("EXEC [dbo].[fsp_CrewFlightDetails] @RM_UserId=?, @SubmissionId=?, @LastDays=?,  @Days=?",RM_UserId,SubmissionId,LastDays,NextDays)
    return responseMaker(prepareJson(rows, cols), "success", 200, "CrewFlights")

def routeChangeReasonEnum():
    data,rows,cols =  dbGetRMeLOG("EXEC [dbo].[fsp_ChangeReasonEnum]")
    return responseMaker(prepareJson(rows, cols), "success", 200, "ChangeReasonEnum")   

def routeCrewSubmitFlightLog(FlightLegId, FlightKey, RM_UserId, CrewPosition, CrewAction,
                           FlightDate, FlightNumber, TailNumber, Origin, Destination,
                           DepatureTime,ArrivalTime,InstrumentTime,
                           FlightTimeDay,FlightTimeNight,FlightTimeBoth,DistanceNM,
                           ChocksOff, ChocksOn, Takeoff, Touchdown,
                           PicId, PicName, CopilotId, CopilotName,
                           OrginalTakeoffPilotId, OrginalTakeoffPilotName, OrginalLandingPilotId, OrginalLandingPilotName,
                           CrewRemarks,RejectionReason,RejectionCode,TechLogUrl,
                           DutyCode,ServiceTypeCode):
    resp = dbTransRMeLOG("""
        EXEC fsp_PilotSubmitFlightLog 
            @FlightLegId = ?,
            @FlightKey = ?,
            @RM_UserId = ?,
            @CrewPosition = ?,
            @CrewAction = ?,
            @FlightDate = ?,
            @FlightNumber = ?,
            @TailNumber = ?,
            @Origin = ?,
            @Destination = ?,
            @DepatureTime = ?,
            @ArrivalTime = ?,
            @InstrumentTime = ?,
            @FlightTimeDay = ?,
            @FlightTimeNight = ?,
	        @FlightTimeBoth = ?,
            @DistanceNM = ?,
            @ChocksOff = ?,
            @ChocksOn = ?,
            @Takeoff = ?,
            @Touchdown = ?,
            @PicId = ?,
            @PicName = ?,
            @CopilotId = ?,
            @CopilotName = ?,
            @OrginalTakeoffPilotId = ?,
            @OrginalTakeoffPilotName = ?,
            @OrginalLandingPilotId = ?,
            @OrginalLandingPilotName = ?,
            @CrewRemarks = ?,
            @RejectionReason = ?,
            @RejectionCode = ?,
            @TechLogUrl = ?,
            @DutyCode = ?,
            @ServiceTypeCode = ?
    """, 
    FlightLegId, FlightKey, RM_UserId, CrewPosition, CrewAction,
    FlightDate, FlightNumber, TailNumber, Origin, Destination,
    DepatureTime,ArrivalTime,InstrumentTime,
    FlightTimeDay,FlightTimeNight,FlightTimeBoth,DistanceNM,
    ChocksOff, ChocksOn, Takeoff, Touchdown,
    PicId, PicName, CopilotId, CopilotName,
    OrginalTakeoffPilotId, OrginalTakeoffPilotName, OrginalLandingPilotId, OrginalLandingPilotName,
    CrewRemarks,RejectionReason,RejectionCode,TechLogUrl,
    DutyCode,ServiceTypeCode)
    
    return resp

def routeSubmitTLChanges(SubmissionId, FlightKey,
    OrginalTakeoffPilotId, OrginalTakeoffPilotName, OrginalLandingPilotId, OrginalLandingPilotName,
    SubmittedTakeoffPilotId, SubmittedTakeoffPilotName, SubmittedLandingPilotId, SubmittedLandingPilotName,
    RM_UserId):
    resp = dbTransRMeLOG("""
        EXEC fsp_InsertTLChanges
            @SubmissionId = ?,
            @FlightKey = ?,
            @OrginalTakeoffPilotId = ?,
            @OrginalTakeoffPilotName = ?,
            @OrginalLandingPilotId = ?,
            @OrginalLandingPilotName = ?,
            @SubmittedTakeoffPilotId = ?,
            @SubmittedTakeoffPilotName = ?,
            @SubmittedLandingPilotId = ?,
            @SubmittedLandingPilotName = ?,
            @RM_UserId = ?
        """, SubmissionId, FlightKey,
    OrginalTakeoffPilotId, OrginalTakeoffPilotName, OrginalLandingPilotId, OrginalLandingPilotName,
    SubmittedTakeoffPilotId, SubmittedTakeoffPilotName, SubmittedLandingPilotId, SubmittedLandingPilotName,
    RM_UserId)
    return resp

def routeAdminFlights(LastDays, NextDays, PageNumber, SubmissionId, RejectionType, TailNumber, FlightNumber, Pilot,EntryBy):
    data,rows,cols =  dbGetRMeLOG("""
        EXEC [dbo].[fsp_GetAdminComparativeData]
        @LastDays=?, @NextDays=?, @PageNumber=?, @SubmissionId=?,
        @RejectionType=?, @TailNumber=?, @FlightNumber=?, @Pilot=?,@EntryBy=?
        """,
        LastDays, NextDays, PageNumber, SubmissionId, RejectionType, TailNumber, FlightNumber, Pilot,EntryBy)
    return responseMaker(prepareJson(rows, cols), "success", 200, "AdminFlights")

def routeAdminFilters(LastDays, NextDays, RejectionType, TailNumber, FlightNumber, Pilot,EntryBy):
    data,rows,cols =  dbGetRMeLOG("""
        EXEC [dbo].[fsp_AdminComparitiveFilters]
        @LastDays=?, @NextDays=?,
        @RejectionType=?, @TailNumber=?, @FlightNumber=?, @Pilot=?, @EntryBy=?
        """,
        LastDays, NextDays, RejectionType, TailNumber, FlightNumber, Pilot,EntryBy)
    return responseMaker(prepareJson(rows, cols), "success", 200, "AdminFilters")

def routeAdminHistory(RM_UserId,PageNumber):
    data,rows,cols =  dbGetRMeLOG("""
        EXEC [dbo].[fsp_AdminLogHistory] 
        @RM_UserId=?,@PageNumber=?
        """,RM_UserId,PageNumber)
    return responseMaker(prepareJson(rows, cols), "success", 200, "HistoricFlights")


def routeAdminRosterChanges(SubmissionId):
    data,rows,cols =  dbGetRMeLOG("""
        EXEC [dbo].[fsp_RosterChanges] 
        @SubmissionId=?
        """,
        SubmissionId)
    return responseMaker(prepareJson(rows, cols), "success", 200, "AdminRosterChanges")

def  routeAdminSubmission(SubmissionId, RM_UserId, AdminAction,AdminRemarks,
    AdminChocksOff,AdminChocksOn,AdminTakeoff,AdminTouchdown,
    AdminTakeoffPilotId,AdminTakeoffPilotName,AdminLandingPilotId,AdminLandingPilotName,AdminTailNumber):
    resp = dbTransRMeLOG("""
        EXEC fsp_AdminProcessSubmission 
            @SubmissionId = ?,
            @RM_UserId = ?,
            @AdminAction = ?,
            @AdminRemarks = ?,
            @AdminChocksOff = ?,
            @AdminChocksOn = ?,
            @AdminTakeoff = ?,
            @AdminTouchdown = ?,
            @AdminTakeoffPilotId = ?,
            @AdminTakeoffPilotName = ?,
            @AdminLandingPilotId = ?,
            @AdminLandingPilotName = ?,
            @AdminTailNumber = ?
        """, SubmissionId, RM_UserId, AdminAction,AdminRemarks,
    AdminChocksOff,AdminChocksOn,AdminTakeoff,AdminTouchdown,
    AdminTakeoffPilotId,AdminTakeoffPilotName,AdminLandingPilotId,AdminLandingPilotName,AdminTailNumber)
    return resp
