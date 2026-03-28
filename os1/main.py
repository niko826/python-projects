import os
import time

def forensic_triage(target_path):
   #It check who is running this and where
    user = os.getlogin()
    print(f"Starting Triage as user: {user}")
#It checks if path exists if not it will show error
    if not os.path.exists(target_path):
        print("Error: Target path does not exists.")
        return
    #Here is the list of what we are serching for
    extensions = ['.conf', '.log', '.pdf', '.docx', '.py', '.sh']
    report = []
#Now it scan files in folder with os.walk
    for root, dirs, files in os.walk(target_path):
        for file in files:
            #It combines the folder name (root) and the filename (file) into a complete address that the computer can actually find
            file_path = os.path.join(root, file)

            try:
                #it collects metadata with os.stat
                #file name
                file_info = os.stat(file_path)
                #files size
                file_size_kb = file_info.st_size / 1024
                #last time file was modified
                last_modified = time.ctime(file_info.st_atime)
            
                #Filter Logic
                is_interesting = False
                 
                #it serch if there is file with the extensions we gave him like .py .txt and other
                if any(file.endswith(ext) for ext in extensions):
                    is_interesting = True

                if file_size_kb > 5000:
                    is_interesting = True   

               
                if is_interesting:
                    #now we append everything
                    report.append ({
                         "name": file,
                         "path": file_path,
                         "size": f"{file_size_kb:.2f} KB",
                         "modified": last_modified
                    })
             # if somthing happens it will stop BUT not crash!
            except OSError:
             #if everthing ok continue
             continue

            print(f"scan completed. found {len(report)} items of interest.\n")
            #Thing that we appended in list (report) now we rewatch it one more time and we print it out
            for item in report:
                print(f"FILE: {item['name']}")
                print(f"  PATH: {item['path']}")
                print(f"  SIZE: {item['size']}")
                print(f"  MODIFIED: {item['modified']}")

forensic_triage(".")