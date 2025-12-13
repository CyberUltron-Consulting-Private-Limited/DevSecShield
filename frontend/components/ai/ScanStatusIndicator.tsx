const ScanStatusIndicator = ({ scan_status }: { scan_status: "success" | "failure" | "pending" | "not_started" | string }) => {


    if (scan_status === "success") {
    return (
            <div className='flex flex-row items-center gap-2'>
              <div className="size-2 rounded-full bg-green-500" />
              <span className="text-muted-foreground text-xs">Scan Completed</span>
            </div>
          )
    }
    if (scan_status === "failure") {
        return (
        <div className='flex flex-row items-center gap-2'>
            <div className="size-2 rounded-full bg-red-500" />
            <span className="text-muted-foreground text-xs">Scan Failed</span>
        </div>
        )
    }
    if (scan_status === "pending") {
        return (
        <div className='flex flex-row items-center gap-2'>
            <div className="size-2 rounded-full bg-yellow-500 animate-pulse duration-500" />
            <span className="text-muted-foreground text-xs">Scan Pending</span>
        </div>
        )
    }
    if (scan_status === "not_started") {
        return (
        <div className='flex flex-row items-center gap-2'>
            <div className="size-2 rounded-full bg-blue-500" />
            <span className="text-muted-foreground text-xs">Scan Not Started</span>
        </div>
        )
    }
    return (
        <div className='flex flex-row items-center gap-2'>
            <div className="size-2 rounded-full bg-blue-500" />
            <span className="text-muted-foreground text-xs">Unknown Status</span>
        </div>
        )
}

export default ScanStatusIndicator;