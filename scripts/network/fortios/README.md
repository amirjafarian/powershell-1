# Firewall configuration
    config system accprofile
        edit "read_profile"
            set mntgrp read
            set admingrp read
            set updategrp read
            set authgrp read
            set sysgrp read
            set netgrp read
            set loggrp read
            set routegrp read
            set fwgrp read
            set vpngrp read
            set utmgrp read
            set wanoptgrp read
            set endpoint-control-grp read
            set wifi read
        next
    end
    config system admin
        edit "config"
            set trusthost1 <specify trusted subnets>
            set accprofile "read_profile"
            set vdom "root"
            set password ENC <encrypted password>
        next
    end

# CSV format

"HostAddress","SSHPort","ClientName","ClientSite","LastBackupStatus","LastBackupAttempt","LastSuccessBackupTime","LastBackupConfigFile"

"192.168.1.254","66","Contoso Inc","Sydney"