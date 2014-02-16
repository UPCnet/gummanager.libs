from functools import partial
import weakref
from StringIO import StringIO
from cStringIO import OutputType as cStringIO
from sh import StreamBufferer
from sh import Logger
import inspect

from _ldap import LdapServer
from _oauth import OauthServer
from _max import MaxServer
from _genweb import GenwebServer

# Patch for sh to accept a partial as a argument


def patched__init__(
        self, name, process, stream, handler, buffer, bufsize,
        pipe_queue=None, save_data=True):
    self.name = name
    self.process = weakref.ref(process)
    self.stream = stream
    self.buffer = buffer
    self.save_data = save_data
    self.encoding = process.call_args["encoding"]
    self.decode_errors = process.call_args["decode_errors"]

    self.pipe_queue = None
    if pipe_queue: self.pipe_queue = weakref.ref(pipe_queue)

    self.log = Logger("streamreader", repr(self))

    self.stream_bufferer = StreamBufferer(
        self.encoding, bufsize,
        self.decode_errors)

    # determine buffering
    if bufsize == 1: self.bufsize = 1024
    elif bufsize == 0: self.bufsize = 1
    else: self.bufsize = bufsize


    # here we're determining the handler type by doing some basic checks
    # on the handler object
    self.handler = handler
    if callable(handler): self.handler_type = "fn"
    elif isinstance(handler, StringIO): self.handler_type = "stringio"
    elif isinstance(handler, cStringIO):
        self.handler_type = "cstringio"
    elif hasattr(handler, "write"): self.handler_type = "fd"
    else: self.handler_type = None


    self.should_quit = False

    # here we choose how to call the callback, depending on how many
    # arguments it takes.  the reason for this is to make it as easy as
    # possible for people to use, without limiting them.  a new user will
    # assume the callback takes 1 argument (the data).  as they get more
    # advanced, they may want to terminate the process, or pass some stdin
    # back, and will realize that they can pass a callback of more args
    if self.handler_type == "fn":
        implied_arg = 0
        if inspect.ismethod(handler):
            implied_arg = 1
            num_args = len(inspect.getargspec(handler).args)

        else:
            if inspect.isfunction(handler):
                num_args = len(inspect.getargspec(handler).args)

            # is an object instance with __call__ method
            else:
                if isinstance(handler, partial):
                    num_args = len(inspect.getargspec(handler.func).args)
                else:
                    implied_arg = 1
                    num_args = len(inspect.getargspec(handler.__call__).args)


        self.handler_args = ()
        if num_args == implied_arg + 2:
            self.handler_args = (self.process().stdin,)
        elif num_args == implied_arg + 3:
            self.handler_args = (self.process().stdin, self.process)


from sh import StreamReader
StreamReader.__init__ = patched__init__
