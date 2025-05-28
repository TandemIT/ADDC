<#

.SYNOPSIS
    Adds a new users to the system.
.DESCRIPTION    
    This script adds a new user to the system based on the provided CSV file.
.PARAMETER CsvFile
    The path to the CSV file containing user information.
.EXAMPLE
    .\new-user.ps1 -CsvFile "C:\path\to\users.csv"
.PARAMETER UserName
    The username of the new user to be added.
.PARAMETER Password
    The password for the new user.
.PARAMETER FullName
    The full name of the new user.
.PARAMETER Email
    The email address of the new user.
.PARAMETER Department
    The department of the new user.
.PARAMETER Phone
    The phone number of the new user.
.PARAMETER Role

#>