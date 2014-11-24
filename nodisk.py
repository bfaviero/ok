import os
import subprocess

H_NAME = 'oauth-kerberos-server'
H_FOLDER = os.path.join('/cgroup', H_NAME)

CGROUP_NAME = 'thegroup'
CGROUP_FOLDER = os.path.join(H_FOLDER, CGROUP_NAME)

MOUNT_CMD_PATH = '/bin/mount'
UMOUNT_CMD_PATH = '/bin/umount'
MOUNTPOINT_CMD_PATH = '/bin/mountpoint'

def prevent_swapping():
	"""prevents the calling process (and any children spawned after
	calling) from being swapped out in whole or in part

	This is done by creating a Linux cgroup which the calling process is 
	added to, then setting the memory.swappiness value for the cgroup to 0. 
	According to the cgroup documentation, this accomplishes the desire
	effect.

	The calling process must be root (have euid 0), but it is fine if the 
	process drops privelidges after calling this."""

	if os.geteuid() != 0:
		raise Exception("you must have effective uid 0 to run this")

	# setup cgroup folders if they don't already exist
	makedirs(H_FOLDER, 0o700, NO_ERROR_IF_EXISTING) # only root

	# mount cgroup heierarchy, if it isn't already mounted
	if mountpoint(H_FOLDER)!=0:
		code = mount('-t', 'cgroup', '-o', 'memory', H_NAME,  H_FOLDER)
		if code != 0:
			raise Exception("unable to create cgroup using mount")
	
	# make the cgroup if it doesn't exist
	makedirs(CGROUP_FOLDER, 0o700, NO_ERROR_IF_EXISTING)

	# set memory.swappiiness to 0 for the cgroup
	f = open(os.path.join(CGROUP_FOLDER, 'memory.swappiness'), 'w')
	f.write('0')
	f.close() # we don't need the file anymore, plus we want the write to be flushedyy

	# add our pid to the cgroup
	f = open(os.path.join(CGROUP_FOLDER, 'tasks'), 'w')
	f.write(str(os.getpid()))
	f.close() # we don't need the file anymore, plus we want the write to be flushedyy
	

ERROR_IF_EXISTING = 0 # raise an error if leaf exists
NO_ERROR_IF_EXISTING = 1 # don't raise an error if leaf exists
def makedirs(path, mode=0o777, behavior=ERROR_IF_EXISTING):
	"""this does the same thing as os.makedirs, but offers the option to
	change the behavior in the event that the leaf directory to be created
	already exists"""

	try:
		os.makedirs(path, mode)
	except OSError as e:
		# If we encountered error because file exists, everything is
		# fine. Otherwise, re-throw the exception
		if e.errno != 17 or behavior==ERROR_IF_EXISTING:
			raise e


def mount(*argv):
	"""calls the mount command with the given arguments, returning whatever
	the mount command returns"""
	return subprocess.call([MOUNT_CMD_PATH] + list(argv))


def umount(*argv):
	"""calls the umount command with the given arguments, returning whatever
	the mount command returns"""
	return subprocess.call([UMOUNT_CMD_PATH] + list(argv))

def mountpoint(dirname):
	"""calls the mountpoint comand with the -q (quiet) argument followed by the dirname
	argument, returning whatever the command returns"""
	return subprocess.call([MOUNTPOINT_CMD_PATH, '-q', dirname])
