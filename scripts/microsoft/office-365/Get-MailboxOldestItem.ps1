Get-MailboxFolderStatistics -IncludeOldestAndNewestItems -Identity <mailbox> | 
    Where OldestItemReceivedDate -ne $null | 
    Sort OldestItemReceivedDate | 
    Select -First 1 OldestItemReceivedDate