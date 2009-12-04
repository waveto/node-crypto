import Options
from os import unlink, symlink, popen
from os.path import exists 

srcdir = "."
blddir = "build"
VERSION = "0.0.3"

def set_options(opt):
  opt.tool_options("compiler_cxx")
  opt.tool_options("compiler_cc")

def configure(conf):
  conf.check_tool("compiler_cxx")
  conf.check_tool("compiler_cc")
  conf.check_tool("node_addon")

  conf.check(lib='ssl', libpath=['/usr/lib', '/usr/local/lib'], uselib_store='OPENSSL')

def build(bld):
  obj = bld.new_task_gen("cxx", "shlib", "node_addon")
  obj.target = "crypto"
  obj.source = "crypto.cc"
  obj.uselib = "OPENSSL"



def shutdown():
  # HACK to get crypto.node out of build directory.
  # better way to do this?
  if Options.commands['clean']:
    if exists('crypto.node'): unlink('crypto.node')
  else:
    if exists('build/default/crypto.node') and not exists('crypto.node'):
      symlink('build/default/crypto.node', 'crypto.node')
