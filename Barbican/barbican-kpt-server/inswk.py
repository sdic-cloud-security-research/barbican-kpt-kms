import ctypes

def swk_provision(swk):
	kpttool = ctypes.CDLL('./libkpttool.so')
	prFilePath = './ngx_priv'
	puFilePath = './ngx_pub'

	rval = kpttool.init_KptRmContext(1)
	print('init:',rval)

	keyLen = 128
	rval = kpttool.FlushAllLoadedObjs()
	print('flush:',rval)

	rval = kpttool.soft_init_swk(swk, keyLen, prFilePath, puFilePath)
	print('initswk',rval)
	if (rval==0):
    	print('INFO:SWK provison succeed!')
	else:
    	print('ERROR:SWK provision failed,error code is',rval)
	
	with open(prFilePath) as file_object:
        swk_priv = file_object.read()
    with open(puFilePath) as file_object:
        swk_pub = file_object.read()
    return swk_priv, swk_pub