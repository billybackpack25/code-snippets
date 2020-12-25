#!/usr/bin/env bash
# ./get_qradar_inactive_accounts.sh--This will get the users that need to be e-mailed for not logging in in X days
# Devices/path: This needs to be run on the QRadar console
# Original Author/date: Bilal Hasson; 2020-12-23
#_________________________________________________________________________ 
PROGRAM=${0##*/}
re='^[0-9]+$'
l='^l$'
h='^--help|-h'

function usage { 
    echo -e "\nUsage: ./$PROGRAM <DAYS> OR ./$PROGRAM l <DAYS> \n \nExplaination: This check will get the list of users who haven't logged in for N days. \nExample: ./$PROGRAM 30\n" >&2;
}

function notANum {
    echo -e "\nERROR: Not a number. Please enter inactivity in days e.g. 30" >&2; usage ;
}

# This script needs to be ran as sudo
if [ "$EUID" -ne 0 ] ; then 
    echo "Please run as root"
    exit 1
fi

# There needs to be at least one argument
if [ "$#" -lt "1" ] ; then
    usage ; exit 3
fi

if [[ $1 =~ $h ]] ; then
    usage ; exit 3
fi
# If the first argument is 'l' then list the user table
if [[ $1 =~ $l ]] ; then
    # There needs to be another argument
    if [ "$#" -lt "2" ] ; then
        usage ; exit 3
    fi
    # It has to be a number
    if [[ $2 =~ $re ]] ; then
        DAYS=$2
        echo ""
        /bin/psql -U qradar -c "select distinct on (user_id) login_attempts.user_id, login_attempts.attempt_time, users.username from login_attempts inner join users on login_attempts.user_id=users.id where user_id not in (select user_id from login_attempts where attempt_time > 'now'::date - '$DAYS days'::interval) order by user_id, attempt_time desc;" >&2; exit 0
    else
        # Exit if it's not a number
        notANum ; exit 1
    fi

# If a single argument is needs to be a number 
elif ! [[ $1 =~ $re ]] ; then
   notANum ; exit 1
fi

if [[ $1 =~ $re ]] ; then
    DAYS=$1
    if [ "$#" -gt "1" ] ; then
        usage ; exit 3
    fi
fi

# Between 0 and 300
if [ "$DAYS" -ge "300" ] ; then
    echo -e "\nERROR: Days cannot 300 or over" >&2; exit 1
elif [ "$DAYS" -le "0" ] ; then
    echo -e "\nERROR: Days cannot be 0 or under" >&2; exit 1
fi

# Array of results
declare -a result=($(psql -U qradar -At -c "select distinct on (user_id) login_attempts.user_id, users.username from login_attempts inner join users on login_attempts.user_id=users.id where user_id not in (select user_id from login_attempts where attempt_time > 'now'::date - '$DAYS days'::interval) order by user_id, attempt_time desc;" | tr ' ' '_'))

# Arrays of account names and e-mails
noEmail=()
emailFound=()

# Loop through the results
for line in ${result[@]} 
do
    userId=$(echo $line | cut -d'|' -f1)
    username=$(echo $line | cut -d'|' -f2)
    email=$(psql -U qradar -tAc "SELECT email from user_settings WHERE id=$userId")
    if [ -z $email ]
    then
        noEmail+=($username)
    else
        emailFound+=($email)
    fi
done

# Join function to join an array with a delimiter
function join_by { local d=$1; shift; local f=$1; shift; printf %s "$f" "${@/#/$d}"; }

# If there were e-mails not found
if ! [ -z $noEmail ] ; then
    echo -e "\nCan't find e-mail for: $(join_by ', ' ${noEmail[*]})\n"
fi 

# If there were mails found
if ! [ -z $emailFound ] ; then
    echo -e "\nThese people haven't logged in for $DAYS days: $(join_by ', ' ${emailFound[*]})\n"
fi

# If neither was found
if [ -z $noEmail ] && [ -z $emailFound ] ; then
    echo -e "\nNo users found, all good. OK\n"
fi

exit 0