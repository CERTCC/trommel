import argparse
import os
from datetime import datetime
import indicators

parser = argparse.ArgumentParser(description= "TROMMEL: Sift Through Directories of Files to Identify Indicators That May Contain Vulnerabilities")
parser.add_argument("-p","--path", required=True, help="Directory to Search")
parser.add_argument("-o","--output", required=True, help="Output Trommel Results File Name (no spaces)")

args = vars(parser.parse_args())

path = args['path']
output = args['output']


#Date informtion
yrmoday = datetime.now().strftime("%Y%m%d_%H%M%S")

#Save file name and date information to file in working directory script
trommel_output =  file(output+'_TROMMEL_'+yrmoday,'wt')


#Main function		
def main():
	#Print information to terminal
	print "\nTROMMEL is working to sift through the directory of files.\nResults will be saved to '%s_TROMMEL_%s'\n" % (output, yrmoday)
	
	#Title written to file
	trommel_output.write('''

 :::==== :::====  :::====  :::=======  :::=======  :::===== :::     
 :::==== :::  === :::  === ::: === === ::: === === :::      :::     
   ===   =======  ===  === === === === === === === ======   ===     
   ===   === ===  ===  === ===     === ===     === ===      ===     
   ===   ===  ===  ======  ===     === ===     === ======== ========
                                                                                                                                                              

''')
	
	#User given name and path to user given directory to search
	trommel_output.write("TROMMEL Results File Name: %s\nDirectory: %s\n" % (output,path))
	
	#Count number of files within given path directory
	total = 0
	for root, dirs, files in os.walk(path, followlinks=False):
		total += len(files)
	trommel_output.write("There are %d total files within the directory.\n\n" % total)
	
	#Disclaimer written to output file
	trommel_output.write("Results could be vulnerabilities. These results should be verified as false positives may exist.\n\n")
		
    #Enumerate dir passed by user
	for root, dirs, files in os.walk(path):
		
		for names in files:
			ff = os.path.join(root,names)
			
			#Ignore any symlinks
			if not os.path.islink(ff):
				
				#Ignore the /dev directory. Script has problems with files in this directory
				dev_kw = "/dev/"
				if not dev_kw in ff:
				
					if path and output: 
						indicators.kw(ff, trommel_output, names)
						
							
if __name__ == '__main__':
    main()