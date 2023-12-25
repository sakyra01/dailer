def print_banner():
    class BColors():
        banner = '\033[93m'
        info = '\033[92m'
        usage = '\033[91m'
        standart = '\033[0m'

    print(f"""{BColors.banner}                                                   
                ,---,                           ,--,                       
              .'  .' `\                ,--,   ,--.'|                       
            ,---.'     \             ,--.'|   |  | :               __  ,-. 
            |   |  .`\  |            |  |,    :  : '             ,' ,'/ /| 
            :   : |  '  |  ,--.--.   `--'_    |  ' |      ,---.  '  | |' | 
            |   ' '  ;  : /       \  ,' ,'|   '  | |     /     \ |  |   ,' 
            '   | ;  .  |.--.  .-. | '  | |   |  | :    /    /  |'  :  /   
            |   | :  |  ' \__\/: . . |  | :   '  : |__ .    ' / ||  | '    
            '   : | /  ;  ," .--.; | '  : |__ |  | '.'|'   ;   /|;  : |    
            |   | '` ,/  /  /  ,.  | |  | '.'|;  :    ;'   |  / ||  , ;    
            ;   :  .'   ;  :   .'   \;  :    ;|  ,   / |   :    | ---'     
            |   ,.'     |  ,     .-./|  ,   /  ---`-'   \   \  /           
            '---'        `--`---'     ---`-'             `----'                                                              
                                    Version 3.0
        """)

    print(f"""{BColors.info}    
    [INFO]
    Dailer - tool which scan DefectDojo findings with different options
    You have 5 options:
        1. Run program with flag -a/--all to scan all (ACTIVE) findings with adding tags.
        2. Run program with flag -pa/--partial to scan (ACTIVE) findings only with CVE for last 3 years and update tags.
        3. Run program with flag -l/--last to scan (ACTIVE) findings only for last days. You could add argument how many days you need. Default value is 0.
        4. Run program with flag -rm/--remove_tags to remove all tags from all findings.
        5. Run program with sub flag -re/--report to add alerting about critical vulnerabilities and make report file with statistics. 
        """)
    print(f"""{BColors.usage}    
    [USAGE]
    To select the operating mode, you need to make such an entry:
            ~$ python3 dailer.py [-h/--help]                (help guide)
            ~$ python3 dailer.py [-a/-all]                  (1-st option)
            ~$ python3 dailer.py [-pa/--partial]            (2-nd option)
            ~$ python3 dailer.py [-l/--last]                (3-nd option)
            ~$ python3 dailer.py [-rm/--remove_tags]        (4-th option)
            ~$ python3 dailer.py [-l/--last] [-re/--report] (5-th option)
        """)
    print(f"{BColors.standart}")
    