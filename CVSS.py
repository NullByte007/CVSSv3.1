import os
import sys

# global variables
vulnerability_name = "--"
status  = "?"
av_type = "--"
av_val  = "--"
ac_type = "--"
ac_val  = "--"
pr_type = "--"
pr_val  = "--"
ui_type = "--"
ui_val  = "--"
s_type  = "--" 
s_val   = "--"
c_type  = "--"
c_val   = "--"
i_type  = "--"
i_val   = "--"
a_type  = "--"
a_val   = "--"
iss     = "--"
ips     = "--"
exploitability_score = "--"
base_score = "--"
severity = "--"



# Base Metric Values
base_metric_values = {
        
        # Attack Vector
        'av_n' : 0.85,
        'av_a' : 0.62,
        'av_l' : 0.55,
        'av_p' : 0.2,

        # Attack complexity
        'ac_l' : 0.77,
        'ac_h' : 0.44,

        #Privileges required
        'pr_n' : 0.85,
        'pr_l' : 0.62,
        'pr_h' : 0.27,
        'pr_l_sc' : 0.68, # if scope changed : 0.68
        'pr_h_sc' : 0.5, # if scope changed : 0.5

        # UI Interaction
        'ui_n' : 0.85,
        'ui_r' : 0.62,

        # Scope
        's_u' : 0.0,
        's_c' : 1.0,

        # Confidentiality Impact
        'c_n' : 0.0,
        'c_l' : 0.22,
        'c_h' : 0.56,


        # Integrity Impact
        'i_n' : 0.0,
        'i_l' : 0.22,
        'i_h' : 0.56,

        #
        'a_n' : 0.0,
        'a_l' : 0.22,
        'a_h' : 0.56,

}

"""

Attack Vector (AV): Network (0.85)
Attack Complexity (AC): Low (0.77)
Privileges Required (PR): None (0.85)
User Interaction (UI): None (0.85)
Scope (S): Unchanged (0.0)
Confidentiality (C): Low (0.22)
Integrity (I): None (0.00)
Availability (A): None (0.00)
"""

precalculated_cvss_collection = {

    '1' : {
        'name' : "LOCAL FILE INCLUSION (LFI)",
        'av_type'  : 'N',
        'av_val' : 0.85,
        'ac_type'  : 'L',
        'ac_val' : 0.77,
        'pr_type'  : 'N',
        'pr_val' : 0.85,
        'ui_type'  : 'N',
        'ui_val' : 0.85,
        's_type'   : 'U',
        's_val'  : 0.0,
        'c_type'   : 'L',
        'c_val'  : 0.22,
        'i_type'   : 'N',
        'i_val'  : 0.0,
        'a_type'   : 'N',
        'a_val'  : 0.0      
    },

   '2' : {
        'name' : "REMOTE FILE INCLUSION (RFI)",
        'av_type' : 'N',
        'av_val' : 0.85,
        'ac_type' : 'L',
        'ac_val' : 0.77,
        'pr_type' : 'N',
        'pr_val' : 0.85,
        'ui_type' : 'N',
        'ui_val' : 0.85,
        's_type' : 'C',
        's_val' : 1.08,
        'c_type' : 'H',
        'c_val' : 0.56,
        'i_type' : 'H',
        'i_val' : 0.56,
        'a_type' : 'H',
        'a_val' : 0.56
    },


   '3' : {
        'name' : "SQL INJECTION (SQLi)",
        'av_type' : 'N',
        'av_val' : 0.85,
        'ac_type' : 'L',
        'ac_val' : 0.77,
        'pr_type' : 'N',
        'pr_val' : 0.85,
        'ui_type' : 'N',
        'ui_val' : 0.85,
        's_type' : 'C',
        's_val' : 1.08,
        'c_type' : 'H',
        'c_val' : 0.56,
        'i_type' : 'H',
        'i_val' : 0.56,
        'a_type' : 'H',
        'a_val' : 0.56

    },



   '4' : {
        'name' : " BLIND SQL INJECTION (SQLi)",
        'av_type' : 'N',
        'av_val' : 0.85,
        'ac_type' : 'L',
        'ac_val' : 0.77,
        'pr_type' : 'N',
        'pr_val' : 0.85,
        'ui_type' : 'N',
        'ui_val' : 0.85,
        's_type' : 'C',
        's_val' : 1.08,
        'c_type' : 'H',
        'c_val' : 0.56,
        'i_type' : 'L',
        'i_val' : 0.22,
        'a_type' : 'L',
        'a_val' : 0.22

    },

   '5' : {
        'name' : "CROSS SITE SCRIPTING (XSS) - REFLECTED",
        'av_type' : 'N',
        'av_val' : 0.85,
        'ac_type' : 'L',
        'ac_val' : 0.77,
        'pr_type' : 'N',
        'pr_val' : 0.85,
        'ui_type' : 'R',
        'ui_val' : 0.62,
        's_type' : 'U',
        's_val' : 0.00,
        'c_type' : 'L',
        'c_val' : 0.22,
        'i_type' : 'L',
        'i_val' : 0.22,
        'a_type' : 'N',
        'a_val' : 0.00
    },

   '6' : {
        'name' : "CROSS SITE SCRIPTING (XSS) - STORED",
        'av_type' : 'N',
        'av_val' : 0.85,
        'ac_type' : 'L',
        'ac_val' : 0.77,
        'pr_type' : 'N',
        'pr_val' : 0.85,
        'ui_type' : 'R',
        'ui_val' : 0.62,
        's_type' : 'U',
        's_val' : 0.00,
        'c_type' : 'L',
        'c_val' : 0.22,
        'i_type' : 'L',
        'i_val' : 0.22,
        'a_type' : 'L',
        'a_val' : 0.22   
    },

   '7' : {
        'name' : "CROSS SITE SCRIPTING (XSS) - DOM BASED",
        'av_type' : 'N',
        'av_val' : 0.85,
        'ac_type' : 'L',
        'ac_val' : 0.77,
        'pr_type' : 'N',
        'pr_val' : 0.85,
        'ui_type' : 'R',
        'ui_val' : 0.62,
        's_type' : 'U',
        's_val' : 0.00,
        'c_type' : 'L',
        'c_val' : 0.22,
        'i_type' : 'L',
        'i_val' : 0.22,
        'a_type' : 'N',
        'a_val' : 0.00

    },

   '8' : {
        'name' : "SERVER SIDE TEMPLATE INJECTION (SSTI)",
        'av_type' : 'N',
        'av_val' : 0.85,
        'ac_type' : 'L',
        'ac_val' : 0.77,
        'pr_type' : 'N',
        'pr_val' : 0.85,
        'ui_type' : 'N',
        'ui_val' : 0.85,
        's_type' : 'C',
        's_val' : 1.08,
        'c_type' : 'H',
        'c_val' : 0.56,
        'i_type' : 'H',
        'i_val' : 0.56,
        'a_type' : 'H',
        'a_val' : 0.56
    },

   '9' : {
        'name' : "COMMAND INJECTION (BASIC)",
        'av_type' : 'N',
        'av_val' : 0.85,
        'ac_type' : 'L',
        'ac_val' : 0.77,
        'pr_type' : 'N',
        'pr_val' : 0.85,
        'ui_type' : 'N',
        'ui_val' : 0.85,
        's_type' : 'C',
        's_val' : 1.08,
        'c_type' : 'H',
        'c_val' : 0.56,
        'i_type' : 'H',
        'i_val' : 0.56,
        'a_type' : 'H',
        'a_val' : 0.56
    },

   '10' : {
        'name' : "COMMAND INJECTION (BLIND)",
        'av_type' : 'N',
        'av_val' : 0.85,
        'ac_type' : 'L',
        'ac_val' : 0.77,
        'pr_type' : 'N',
        'pr_val' : 0.85,
        'ui_type' : 'N',
        'ui_val' : 0.85,
        's_type' : 'C',
        's_val' : 1.08,
        'c_type' : 'H',
        'c_val' : 0.56,
        'i_type' : 'L',
        'i_val' : 0.22,
        'a_type' : 'L',
        'a_val' : 0.22
    },

   '11' : {
        'name' : "XML EXTERNAL ENTITY (XXE)",
        'av_type' : 'N',
        'av_val' : 0.85,
        'ac_type' : 'L',
        'ac_val' : 0.77,
        'pr_type' : 'N',
        'pr_val' : 0.85,
        'ui_type' : 'N',
        'ui_val' : 0.85,
        's_type' : 'C',
        's_val' : 1.08,
        'c_type' : 'H',
        'c_val' : 0.56,
        'i_type' : 'L',
        'i_val' : 0.22,
        'a_type' : 'L',
        'a_val' : 0.22
    },

   '12' : {
        'name' : "INSECURE FILE UPLOAD BYPASS",
        'av_type' : 'N',
        'av_val' : 0.85,
        'ac_type' : 'L',
        'ac_val' : 0.77,
        'pr_type' : 'N',
        'pr_val' : 0.85,
        'ui_type' : 'N',
        'ui_val' : 0.85,
        's_type' : 'C',
        's_val' : 1.08,
        'c_type' : 'H',
        'c_val' : 0.56,
        'i_type' : 'H',
        'i_val' : 0.56,
        'a_type' : 'H',
        'a_val' : 0.56
    },

   '13' : {
        'name' : "CROSS SIDE REQUEST FORGERY (CSRF)",
        'av_type' : 'N',
        'av_val' : 0.85,
        'ac_type' : 'L',
        'ac_val' : 0.77,
        'pr_type' : 'N',
        'pr_val' : 0.85,
        'ui_type' : 'R',
        'ui_val' : 0.62,
        's_type' : 'U',
        's_val' : 0.00,
        'c_type' : 'L',
        'c_val' : 0.22,
        'i_type' : 'L',
        'i_val' : 0.22,
        'a_type' : 'N',
        'a_val' : 0.00
    },

   '14' : {
        'name' : "SERVER SIDE REQUEST FORGERY (SSRF)",
        'av_type' : 'N',
        'av_val' : 0.85,
        'ac_type' : 'L',
        'ac_val' : 0.77,
        'pr_type' : 'N',
        'pr_val' : 0.85,
        'ui_type' : 'N',
        'ui_val' : 0.85,
        's_type' : 'C',
        's_val' : 1.08,
        'c_type' : 'H',
        'c_val' : 0.56,
        'i_type' : 'L',
        'i_val' : 0.22,
        'a_type' : 'L',
        'a_val' : 0.22
    },

   '15' : {
        'name' : "SERVER SIDE REQUEST FORGERY (SSRF) BLIND",
        'av_type' : 'N',
        'av_val' : 0.85,
        'ac_type' : 'L',
        'ac_val' : 0.77,
        'pr_type' : 'N',
        'pr_val' : 0.85,
        'ui_type' : 'N',
        'ui_val' : 0.85,
        's_type' : 'C',
        's_val' : 1.08,
        'c_type' : 'L',
        'c_val' : 0.22,
        'i_type' : 'L',
        'i_val' : 0.22,
        'a_type' : 'L',
        'a_val' : 0.22
    },

   '16' : {
        'name' : "SUBDOMAIN TAKEOVER",
        'av_type' : 'N',
        'av_val' : 0.85,
        'ac_type' : 'L',
        'ac_val' : 0.77,
        'pr_type' : 'N',
        'pr_val' : 0.85,
        'ui_type' : 'N',
        'ui_val' : 0.85,
        's_type' : 'C',
        's_val' : 1.08,
        'c_type' : 'H',
        'c_val' : 0.56,
        'i_type' : 'H',
        'i_val' : 0.56,
        'a_type' : 'H',
        'a_val' : 0.56
    },

   '17' : {
        'name' : "OPEN REDIRECTS",
        'av_type' : 'N',
        'av_val' : 0.85,
        'ac_type' : 'L',
        'ac_val' : 0.77,
        'pr_type' : 'N',
        'pr_val' : 0.85,
        'ui_type' : 'R',
        'ui_val' : 0.62,
        's_type' : 'U',
        's_val' : 0.00,
        'c_type' : 'N',
        'c_val' : 0.00,
        'i_type' : 'N',
        'i_val' : 0.00,
        'a_type' : 'N',
        'a_val' : 0.00
    },


}



def show_title_banner():
    os.system("clear")
    title_banner = """ 
    +========================================================================+
    |   ░█████╗░██╗░░░██╗░██████╗░██████╗      ██╗░░░██╗██████╗░░░░░░███╗░░  |
    |   ██╔══██╗██║░░░██║██╔════╝██╔════╝      ██║░░░██║╚════██╗░░░░████║░░  |
    |   ██║░░╚═╝╚██╗░██╔╝╚█████╗░╚█████╗░      ╚██╗░██╔╝░█████╔╝░░░██╔██║░░  |
    |   ██║░░██╗░╚████╔╝░░╚═══██╗░╚═══██╗      ░╚████╔╝░░╚═══██╗░░░╚═╝██║░░  |
    |   ╚█████╔╝░░╚██╔╝░░██████╔╝██████╔╝      ░░╚██╔╝░░██████╔╝██╗███████╗  |
    |   ░╚════╝░░░░╚═╝░░░╚═════╝░╚═════╝░      ░░░╚═╝░░░╚═════╝░╚═╝╚══════╝  |
    +========================================================================+
    | Code by : Aniket Bhagwate | [NullByte007]                              |
    +========================================================================+
    """
    print(title_banner)




def show_main_banner():
    
    main_banner = """
    +========================================================================+
    |   ░█████╗░██╗░░░██╗░██████╗░██████╗      ██╗░░░██╗██████╗░░░░░░███╗░░  |
    |   ██╔══██╗██║░░░██║██╔════╝██╔════╝      ██║░░░██║╚════██╗░░░░████║░░  |
    |   ██║░░╚═╝╚██╗░██╔╝╚█████╗░╚█████╗░      ╚██╗░██╔╝░█████╔╝░░░██╔██║░░  |
    |   ██║░░██╗░╚████╔╝░░╚═══██╗░╚═══██╗      ░╚████╔╝░░╚═══██╗░░░╚═╝██║░░  |
    |   ╚█████╔╝░░╚██╔╝░░██████╔╝██████╔╝      ░░╚██╔╝░░██████╔╝██╗███████╗  |
    |   ░╚════╝░░░░╚═╝░░░╚═════╝░╚═════╝░      ░░░╚═╝░░░╚═════╝░╚═╝╚══════╝  |
    +========================================================================+
    | Code by : Aniket Bhagwate | [NullByte007]                              |
    +========================================================================+

    ------------------------------------------MENU------------------------------------------
    +======================================================================================+
    | [1] PRECALCULATED CVSS VALUES FOR OWASP TOP 10 VULNERABILITIES                       |
    +======================================================================================+
    | [2] CALCULATE CVSS MANUALLY                                                          |
    +======================================================================================+
    | [3] RECALCULATE CVSS FOR TOP VULNERABILITIES WITH TEMPORAL AND ENVIRONMENTAL METRICS |
    +======================================================================================+
    | [0] EXIT                                                                             |
    +======================================================================================+
    """
    os.system("clear")
    print(main_banner)


def show_value_banner():
    global vulnerability_name
    global status
    global av_type
    global av_val
    global ac_type
    global ac_val
    global pr_type
    global pr_val
    global ui_type
    global ui_val
    global s_type
    global s_val
    global c_type
    global c_val
    global i_type
    global i_val
    global a_type
    global a_val
    global iss
    global ips
    global exploitability_score
    global base_score
    global severity
    
    show_title_banner()

    print(f"""
    +=========================== BASE Metrics =========================== +

            ============> [ {vulnerability_name} ] <============

    + ################################################################### +
    | [-] ATTACK VECTOR       [AV] => [{av_type}] [{av_val}] 
    + ################################################################### +
    | [-] ATTACK COMPLEXITY   [AC] => [{ac_type}] [{ac_val}]
    + ################################################################### +
    | [-] PRIVILEGES REQUIRED [PR] => [{pr_type}] [{pr_val}]
    + ################################################################### +
    | [-] USER INTERACTION    [UI] => [{ui_type}] [{ui_val}]
    + ################################################################### +
    | [-] SCOPE               [S]  => [{s_type}] [{s_val}]
    + ################################################################### +
    | [-] CONFIDENTIALITY     [C]  => [{c_type}] [{c_val}]
    + ################################################################### +
    | [-] INTEGRITY           [I]  => [{i_type}] [{i_val}]
    + ################################################################### +
    | [-] AVAILABILITY        [A]  => [{a_type}] [{a_val}]
    + ################################################################### +

    + ################################################################### +
    | [--> ] IMPACT SUB SCORE (ISS) = [ {iss} ]
    + ################################################################### +
    | [--> ] IMPACT SCORE = [ {ips} ]
    + ################################################################### +
    | [--> ] EXPLOITABILITY SCORE = [ {exploitability_score} ]
    + ################################################################### +
    | [--> ] BASE SCORE = [ {base_score} ] | SEVERITY : {severity}
    + ################################################################### +

    +==================================================================== +
    + [ -->] Vector  => CVSS:3.1/AV:{av_type}/AC:{ac_type}/PR:{pr_type}/UI:{ui_type}/S:{s_type}/C:{c_type}/I:{i_type}/A:{a_type}
    +==================================================================== +
    
    
    
    
    """)
    #Critical: 9.0 - 10.0
    #High: 7.0 - 8.9
    #Medium: 4.0 - 6.9
    #Low: 0.1 - 3.9
    #None: 0.0


def show_vulnerability_banner():
    show_title_banner()
    
    print("""
    
    +==============================================================================================+
    | [1] LOCAL FILE INCLUSION (LFI)  | [9] COMMAND INJECTION (BASIC)                              |
    +==============================================================================================+
    | [2] REMOTE FILE INCLUSION (RFI) | [10] COMMAND INJECTION (BLIND)                             |
    +==============================================================================================+
    | [3] SQL INJECTION BASIC (SQLi)  | [11] XML EXTERNAL ENTITY (XXE)                             |
    +==============================================================================================+
    | [4] SQL INJECTION BLIND (SQLi)  | [12] INSECURE FILE UPLOAD BYPASS                           |
    +==============================================================================================+
    | [5] CROSS SITE SCRIPTING (XSS) - REFLECTED  | [13] CROSS SIDE REQUEST FORGERY (CSRF)         |
    +==============================================================================================+
    | [6] CROSS SITE SCRIPTING (XSS) - STORED     | [14] SERVER SIDE REQUEST FORGERY (SSRF)        |
    +==============================================================================================+
    | [7] CROSS SITE SCRIPTING (XSS) - DOM BASED  | [15] SERVER SIDE REQUEST FORGERY (SSRF) BLIND  |
    +==============================================================================================+
    | [8] SERVER SIDE TEMPLATE INJECTION (SSTI)   | [16] SUBDOMAIN TAKEOVER | [17] OPEN REDIRECTS  |
    +==============================================================================================+
     

    """)



def severity_checker(base_score):
    if base_score >= 9.0 and base_score <= 10.0:
        return "CRITICAL"
    elif base_score >= 7.0 and base_score <= 8.9:
        return "HIGH"
    elif base_score >= 4.0 and base_score <= 6.9:
        return "MEDIUM"
    elif base_score >= 0.1 and base_score <= 3.9:
        return "LOW"
    elif base_score == 0.0:
        return "NONE"
    


def calculation_block(): # This block wil calculate all the necessary pre-requisites : ISS, Impact score, exploitability score, base score
    global av_type
    global av_val
    global ac_type
    global ac_val
    global pr_type
    global pr_val
    global ui_type
    global ui_val
    global s_type
    global s_val
    global c_type
    global c_val
    global i_type
    global i_val
    global a_type
    global a_val 
    global iss
    global ips
    global exploitability_score
    global base_score  
    global severity 

    c_const = base_metric_values["c_" + c_type.lower()]
    i_const = base_metric_values["i_" + i_type.lower()]
    a_const = base_metric_values["a_" + a_type.lower()]

    iss = round(1-((1-c_const)*(1-i_const)*(1-a_const)),3) # Roundoff till 3 digits after decimal

    if s_type.lower() =="u":
        # scope = Unchanged
        ips=round(6.42*iss,2)
    elif s_type.lower() =="c":
        # scope changed
        ips=round(7.52*(iss-0.029)-3.25*(iss-0.02)**15,2)
    

    exploitability_score = round(8.22*av_val*ac_val*pr_val*ui_val,2)

    if s_type.lower() =="u":
        # scope = Unchanged
        base_score=round(min(ips+exploitability_score,10),1)
        
    elif s_type.lower() =="c":
        # scope changed
        base_score=round(min(1.08*(ips+exploitability_score),10),1)


    severity = severity_checker(base_score)

    #base_score = round(((ips+exploitability_score)>0)*(ips+exploitability_score))
    show_value_banner()
    #print("ISS : " + str(iss))
    #print("Impact Score : " +  str(ips))
    #print("Exploitability : " + str(exploitability_score))
    #print("Base score : " + str(base_score))




def precalculated_cvss():
    global vulnerability_name
    global status
    global av_type
    global av_val
    global ac_type
    global ac_val
    global pr_type
    global pr_val
    global ui_type
    global ui_val
    global s_type
    global s_val
    global c_type
    global c_val
    global i_type
    global i_val
    global a_type
    global a_val 
    global iss
    global ips
    global exploitability_score
    global base_score  
    global severity

    show_title_banner()
    show_vulnerability_banner()
    vulnerability_choice = input("[!] SELECT THE VULNERABILITY : ")
    #print(precalculated_cvss_collection[vulnerability_choice])

    vulnerability_name = precalculated_cvss_collection[vulnerability_choice]['name']
    av_type = precalculated_cvss_collection[vulnerability_choice]['av_type']
    av_val = precalculated_cvss_collection[vulnerability_choice]['av_val']
    ac_type= precalculated_cvss_collection[vulnerability_choice]['ac_type']
    ac_val= precalculated_cvss_collection[vulnerability_choice]['ac_val']
    pr_type= precalculated_cvss_collection[vulnerability_choice]['pr_type']
    pr_val= precalculated_cvss_collection[vulnerability_choice]['pr_val']
    ui_type= precalculated_cvss_collection[vulnerability_choice]['ui_type']
    ui_val= precalculated_cvss_collection[vulnerability_choice]['ui_val']
    s_type= precalculated_cvss_collection[vulnerability_choice]['s_type']
    s_val= precalculated_cvss_collection[vulnerability_choice]['s_val']
    c_type= precalculated_cvss_collection[vulnerability_choice]['c_type']
    c_val= precalculated_cvss_collection[vulnerability_choice]['c_val']
    i_type= precalculated_cvss_collection[vulnerability_choice]['i_type']
    i_val= precalculated_cvss_collection[vulnerability_choice]['i_val']
    a_type= precalculated_cvss_collection[vulnerability_choice]['a_type']
    a_val= precalculated_cvss_collection[vulnerability_choice]['a_val']
    show_title_banner()
    calculation_block()
    input("\n\n[!!!] Press Enter Key !!")




def calculate_manually():
    global vulnerability_name
    global status
    global av_type
    global av_val
    global ac_type
    global ac_val
    global pr_type
    global pr_val
    global ui_type
    global ui_val
    global s_type
    global s_val
    global c_type
    global c_val
    global i_type
    global i_val
    global a_type
    global a_val 
    global iss
    global ips
    global exploitability_score
    global base_score  
    global severity 

    show_value_banner()

    # Vulnerability Name
    vulnerability_name = input("[?] ENTER VULNERABILITY NAME : ")
    show_value_banner()

    # Attack Vector
    av_type = input(" | ATTACK VECTOR | [?] How the vulnerability can be exploited ?\n\n[-] Network (N) : Exploitable remotely over Internet\n[-] Adjacent (A) : Exploitable within the same Network\n[-] Local (L) : Requires local access to the system\n[-] Physical (P) : Requires physical access to the device\n\n ==>  ").upper()
    av_val = base_metric_values["av_" + av_type.lower()]
    show_value_banner()

    # Attack Complexity
    ac_type = input("| ATTACK COMPLEXITY | [?] How difficult is the exploitation ?\n\n[-] Low (L) : No special conditions required, easy to exploit\n[-] High (H) : Needs specific conditions\n\n ==>  ").upper()
    ac_val = base_metric_values["ac_" + ac_type.lower()]
    show_value_banner()

    # Privileges Required
    pr_type = input("| PRIVILEGES REQUIRED | [?] What level of access required ?\n\n[-] None (N) : No authentication needed\n[-] Low (L) : Requires user level access\n[-] High (H) : Requires admin / root access\n\n ==>  ").upper()
    pr_val = base_metric_values["pr_" + pr_type.lower()]
    show_value_banner()

    # User Interaction
    ui_type = input("[?] Does the victim need to take action ?\n\n[-] None (N) : No user action required\n[-] Required (R) : Needs user interaction\n\n ==>  ").upper()
    ui_val = base_metric_values["ui_" + ui_type.lower()]
    show_value_banner()

    # Scope
    s_type = input("[?] Does the exploit affect other systems ?\n\n[-] Unchanged (U) : Stays within the same security boundary\n[-] Changed (C) : Affects other systems\n\n ==>  ").upper()
    s_val = base_metric_values["s_" + s_type.lower()]
    show_value_banner()

    # Confidentiality Impact
    c_type = input("[?] Does it expose sensitive data ?\n\n[-] None (N) : No data is exposed\n[-] Low (L) : Some limited information is leaked\n[-]High (H) : Critical data is leaked\n\n ==>  ").upper()
    c_val = base_metric_values["c_" + c_type.lower()]
    show_value_banner()


    # Integrity Impact
    i_type = input("[?] Can data be modified ?\n\n[-] None (N) : No modification Possible\n[-] Low (L) : Some modification possible\n[-] High (H) : Full data manipulations\n\n ==>  ").upper()
    i_val = base_metric_values["i_" + i_type.lower()]
    show_value_banner()


    # Availability Impact
    a_type = input("[?] Does it affect system uptime ?\n\n[-] None (N) : No user action required\n[-] Low (L) : Some disruption but recoverable\n[-] High (H) : System is fully compromised or crashed\n\n ==>  ").upper()
    a_val = base_metric_values["a_" + a_type.lower()]
    show_value_banner()

    calculation_block() # To show all the calculated values

    input("\n\n[!!!] Press Enter Key !!")
    


    


    
# MAIN BLOCK !!!!!!!!!!!!!!!!!!!!!!!!
def main():
    global vulnerability_name
    global status
    global av_type
    global av_val
    global ac_type
    global ac_val
    global pr_type
    global pr_val
    global ui_type
    global ui_val
    global s_type
    global s_val
    global c_type
    global c_val
    global i_type
    global i_val
    global a_type
    global a_val 
    global iss
    global ips
    global exploitability_score
    global base_score  
    global severity 

    while True:
        show_main_banner()
        
        vulnerability_name = "--"
        status  = "?"
        av_type = "--"
        av_val  = "--"
        ac_type = "--"
        ac_val  = "--"
        pr_type = "--"
        pr_val  = "--"
        ui_type = "--"
        ui_val  = "--"
        s_type  = "--" 
        s_val   = "--"
        c_type  = "--"
        c_val   = "--"
        i_type  = "--"
        i_val   = "--"
        a_type  = "--"
        a_val   = "--"
        iss     = "--"
        ips     = "--"
        exploitability_score = "--"
        base_score = "--"
        severity = "--"
        
        choice  = int(input(" [?] ENTER YOUR CHOICE :  "))
        if choice==1:
            precalculated_cvss()
        elif choice==2:
            calculate_manually()
        elif choice==3:
            sys.exit()

    

if __name__=='__main__':
    main()

