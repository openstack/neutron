# Copyright 2017 Cloudbase Solutions.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import random
import time

import eventlet
from eventlet import tpool
from ovs import winutils as ovs_winutils

import win32con
import win32event
import win32process
import win32security


def avoid_blocking_call(f, *args, **kwargs):
    """Ensure that the method "f" will not block other greenthreads.

    Performs the call to the function "f" received as parameter in a
    different thread using tpool.execute when called from a greenthread.
    This will ensure that the function "f" will not block other greenthreads.
    If not called from a greenthread, it will invoke the function "f" directly.
    The function "f" will receive as parameters the arguments "args" and
    keyword arguments "kwargs".
    """
    # Note that eventlet.getcurrent will always return a greenlet object.
    # In case of a greenthread, the parent greenlet will always be the hub
    # loop greenlet.
    if eventlet.getcurrent().parent:
        return tpool.execute(f, *args, **kwargs)
    else:
        return f(*args, **kwargs)


class WindowsException(Exception):
    """Base Windows Exception

    This class is inherited by all the other exceptions that are used in
    this file. The 'error_message' property should be defined in the class
    that inherits from this with a particular message if needed.
    """
    error_message = None

    def __init__(self, message):
        super(WindowsException, self).__init__()
        # The error message which will be printed for this exception
        self.error_message = message

    def __str__(self):
        return self.error_message


class NamedPipeException(WindowsException):
    """Exception raised when there is an error with the named pipes.

    If there is an error code associated with this exception, it can be
    retrieved by accessing the 'code' property of this class.
    """
    def __init__(self, message, error_code=None):
        super(NamedPipeException, self).__init__(message)
        # The error code associated with this exception. This property should
        # be different than 'None' if there is an existing error code.
        self.code = error_code
        if self.code:
            # Appending the error code to the message
            self.error_message += " Error code: '%s'." % self.code

    def __str__(self):
        return self._error_string


class ProcessException(WindowsException):
    """Exception raised when there is an error with the child process.

    This class inherits the implementation from the super class, it does not
    have anything particular. It is intentionally left blank.
    """
    pass


class NamedPipe(object):
    def __init__(self, pipe_name=None, sec_attributes=-1):
        """Create a named pipe with the given name.

        :param pipe_name(Optional): string representing the name of the pipe
            which should be used to create the named pipe
        :param sec_attributes(Optional): type win32security.SECURITY_ATTRIBUTES
            The default value is -1 which uses the default security attributes.
            This means that the named pipe handle is inherited when a new
            process is created.
        """
        # For reading from the named pipe, we will use an overlapped structure
        # for non-blocking I/O
        self._read = ovs_winutils.pywintypes.OVERLAPPED()
        # Create a new event which will be used by the overlapped structure
        self._read.hEvent = ovs_winutils.get_new_event()
        # This property tells if there is a pending reading operation on
        # the named pipe or not.
        self._read_pending = False

        if pipe_name is None:
            # Generate a random name for the named pipe if the name was not
            # passed explicitly as parameter.
            pipe_name = ("NamedPipe_%d_%s" %
                         (time.time(), str(random.random()).split(".")[1]))

        # Creating the name for a local named pipe. The property "name" will
        # have "\\.\pipe\" appended at the start of pipe_name
        self.name = ovs_winutils.get_pipe_name(pipe_name)
        # This property will contain the handle of the named pipe which can
        # be accessed later on.
        self.namedpipe = ovs_winutils.create_named_pipe(self.name,
                                                        saAttr=sec_attributes)
        # This property should be initialised explicitly later on by calling
        # the method create_file of this class.
        self._npipe_file = None

        if not self.namedpipe:
            # If there was an error when creating the named pipe, the property
            # "namedpipe" should be None. We raise an exception in this case
            raise NamedPipeException("Failed to create named pipe.")

    @property
    def read_overlapped_event(self):
        """Return the event used by the overlapped structure for reading.

        This is the handle(event) on which we should wait if we want to be
        notified when there is something to read from the named pipe.
        """
        return self._read.hEvent

    def _wait_event(self, event, timeout=win32event.INFINITE):
        """Wait until the event is signaled or the timeout has passed."""
        # If greenthreads are used, we need to wrap the call to
        # win32event.WaitForMultipleObjects using avoid_blocking_call to make
        # sure the function will not block the other greenthreads.
        avoid_blocking_call(win32event.WaitForMultipleObjects,
                            [event],
                            False,
                            timeout)

    def wait_for_read(self, timeout=win32event.INFINITE):
        """Wait until there is something to read from the named pipe or the

        timeout passed as parameter has passed.

        :param timeout: int representing the timeout in milliseconds
        """
        if self._read_pending:
            self._wait_event(self._read.hEvent, timeout)

    def create_file(self, sec_attributes=-1):
        """Create the file for the named pipe and store it in the '_npipe_file'

        property of the class.

        :param sec_attributes: type win32security.SECURITY_ATTRIBUTES
            The default value is -1 which uses the default security attributes.
            This means that the file handle will NOT be inherited when
            a new process is created.
        """
        try:
            # Create the file using the name of the named pipe with the given
            # security attributes
            self._npipe_file = ovs_winutils.create_file(
                self.name, attributes=sec_attributes)
            try:
                ovs_winutils.set_pipe_mode(
                    self._npipe_file,
                    ovs_winutils.win32pipe.PIPE_READMODE_BYTE)
            except ovs_winutils.pywintypes.error as e:
                raise NamedPipeException(
                    "Could not set pipe read mode to byte. "
                    "Error: %s." % e.strerror, e.winerror)
        except ovs_winutils.pywintypes.error as e:
            raise NamedPipeException("Could not create file for named pipe. "
                                     "Error: %s." % e.strerror, e.winerror)

    def blocking_write(self, buf, to_namedpipe=True):
        """Write to the named pipe handle or the file handle.

        This function will wait until the write operation has completed.

        :param buf: string representing the buffer which will be written
        :param to_namedpipe: boolean representing where to write the buffer
            True = the buffer 'buf' will be written to the named pipe handle
            False = the buffer 'buf' will be written to the file handle
        """
        if not to_namedpipe and self._npipe_file is None:
            # If the method tries to write to the file handle but the
            # property '_npipe_file' does not contain the file handle then
            # we raise an exception
            raise NamedPipeException("create_file must be called first.")
        # Represents the handle where we should write the buffer
        handle_to_write = self.namedpipe if to_namedpipe else self._npipe_file
        # encoded_buf will contain the buffer 'buf' represented in binary type
        encoded_buf = ovs_winutils.get_encoded_buffer(buf)

        # If greenthreads are used, we need to wrap the call to
        # ovs_winutils.write_file using avoid_blocking_call to make
        # sure the function will not block the other greenthreads.
        (errCode, _nBytesWritten) = avoid_blocking_call(
            ovs_winutils.write_file,
            handle_to_write,
            encoded_buf,
            None)
        if errCode:
            # errCode should be 0 if the operation completed successfully.
            # If we reach here it means there was an error during the write
            # operation and we should raise an exception
            raise NamedPipeException("Could not write to named pipe.", errCode)

    def nonblocking_read(self, bytes_to_read, from_namedpipe=True):
        """Read from the named pipe handle or the file handle.

        This function returns imediatly and does not wait for the read
        operation to complete. In case the read operation is not complete,
        the property '_read_pending' will be set to True and the method
        get_read_result should be called to retrieve the result. Otherwise,
        the output of the read operation is returned.

        :param bytes_to_read: int representing the maximum number of bytes
            to be read.
        :param from_namedpipe: boolean representing from where to read
            True = the function reads from the named pipe handle
            False = he function reads from the file handle
        """
        if self._read_pending:
            # If there is a pending read operation, the method
            # 'get_read_result' should be called to retrieve the result.
            return

        # Represents the handle from where we should read.
        handle_to_read = self.namedpipe if from_namedpipe else self._npipe_file

        # The read operation is non-blocking because the read overlapped
        # structure is passed. It will return immediately.
        (errCode, self._read_buffer) = ovs_winutils.read_file(
            handle_to_read,
            bytes_to_read,
            self._read)

        if errCode:
            # The error code should be 0 if the operation executed with success
            if errCode == ovs_winutils.winerror.ERROR_IO_PENDING:
                # This is returned when the overlapped structure is passed
                # to the read operation (which is our case) and the operation
                # has not finished yet. We mark this as a pending read
                # operation and we will use the method 'get_read_result'
                # later on to retrieve the result.
                self._read_pending = True
            else:
                # In this case we received an unexpected error code, raise
                # an exception.
                raise NamedPipeException(
                    "Could not read from named pipe.", errCode)
            return None

        # If we can not retrieve the output from the overlapped result,
        # it means that the pipe was disconnected so we have no output.
        # The returned value should be an empty string.
        output = ""
        try:
            # Try to retrieve the result from the overlapped structure.
            # This call should succeed or otherwise will raise an exception,
            # but it will not block.
            nBytesRead = ovs_winutils.get_overlapped_result(
                handle_to_read,
                self._read,
                False)
            # Mark the read operation as complete
            self._read_pending = False
            # Retrieve the result and put the decoded result inside the
            # 'output' variable.
            output = ovs_winutils.get_decoded_buffer(
                self._read_buffer[:nBytesRead])
            # We need to manually signal the event to make sure the call to
            # wait for the event will not block.
            win32event.SetEvent(self._read.hEvent)
        except NamedPipeException as e:
            # If the pipe was disconnected, it means no output, we will return
            # an empty string in this case. Otherwise raise an exception.
            if e.code not in ovs_winutils.pipe_disconnected_errors:
                raise e
        return output

    def get_read_result(self, from_namedpipe=True):
        """Return the result from the overlapped structure.

        If there is no pending read operation, this function will return
        immediately. This call will return False if the reading operation
        has not completed yet and the read operation is still in progress.
        Otherwise, it will return the result.

        :param from_namedpipe: boolean representing from where to read
            True = the function reads from the named pipe handle
            False = he function reads from the file handle
        """
        if not self._read_pending:
            # There is no pending read operation, we should return here
            return

        # Represents the handle from where we should read.
        handle_to_read = self.namedpipe if from_namedpipe else self._npipe_file
        try:
            # Try to retrieve the result from the overlapped structure.
            # This will raise an ERROR_IO_INCOMPLETE exception if the
            # read operation has not completed yet.
            nBytesRead = ovs_winutils.get_overlapped_result(handle_to_read,
                                                            self._read,
                                                            False)
            # Mark the read operation as complete
            self._read_pending = False
            # Decode the result and return it
            return ovs_winutils.get_decoded_buffer(
                self._read_buffer[:nBytesRead])
        except ovs_winutils.pywintypes.error as e:
            if e.winerror == ovs_winutils.winerror.ERROR_IO_INCOMPLETE:
                # In this case we should call again this function to try to
                # retrieve the result.
                self._read_pending = True
                # Return False to mark that the read operation has not
                # completed yet.
                return False
            else:
                # If we reach here it means that an unexpected error was
                # received. We should raise an exception in this case.
                raise NamedPipeException(
                    "Could not get the overlapped result. "
                    "Error: '%s'" % e.strerror, e.winerror)

    def close_filehandle(self):
        """Close the file handle."""
        ovs_winutils.close_handle(self._npipe_file)

    def get_file_handle(self):
        """Returns the file handle."""
        return self._npipe_file

    def close_all_handles(self):
        """Close all the handles used by this class."""
        if hasattr(self, "namedpipe") and self.namedpipe:
            ovs_winutils.close_handle(self.namedpipe)
        if hasattr(self, "_read") and self._read.hEvent:
            ovs_winutils.close_handle(self._read.hEvent)
        if hasattr(self, "_npipe_file") and self._npipe_file:
            ovs_winutils.close_handle(self._npipe_file)

    def __del__(self):
        """Make sure all the handles are closed."""
        self.close_all_handles()


class ProcessWithNamedPipes(object):
    class HandleClass(object):
        """This class is used only to provide a 'close' method for the stdin,
        stdout and stderr of the new process. This ensures compatibility with
        the subprocess.Popen returned object.
        """
        def __init__(self, namedpipe):
            self.namedpipe = namedpipe

        def close(self):
            # Close all the handles used
            if self.namedpipe:
                self.namedpipe.close_all_handles()
                self.namedpipe = None

    # The maximum number of bytes to be read
    _BUFSIZE = 16384

    def __init__(self, cmd, env):
        """Create a new process executing 'cmd' and with environment 'env'.

        :param cmd: string representing the command line to be executed
        :param env: instance representing the environment which should be used
            for the new process. Look at 'os.environ' for an example.
        """
        # The startupinfo structure used to spawn the new process
        self._si = win32process.STARTUPINFO()

        # Attributes defined to ensure compatibility with the subprocess.Popen
        # returned object.
        self.returncode = None
        self.stdin = None
        self.stdout = None
        self.stderr = None
        self.pid = None

        # Convert the command to be a single string
        cmd = " ".join(cmd)
        # Initialize the named pipes used for stdin, stdout and stderr
        self._initialize_named_pipes_for_std()
        # Create the child process
        self._start_process(cmd, env)

    def _initialize_named_pipes_for_std(self):
        """Initialize the named pipes used for communication with the child
        process.
        """

        # used in generating the name for the pipe
        pid = os.getpid()

        # Security attributes for the named pipes, should not be inherited
        # by the child process. Those are used by the parent process to
        # communicate with the child process.
        _saAttr_pipe = win32security.SECURITY_ATTRIBUTES()
        _saAttr_pipe.bInheritHandle = 0
        # Security attributes for the file handles, they should be inherited
        # by the child process which will use them as stdin, stdout and stderr.
        # The parent process will close those handles after the child process
        # is created.
        _saAttr_file = win32security.SECURITY_ATTRIBUTES()
        _saAttr_file.bInheritHandle = 1

        def create_namedpipe_and_file(prefix, saAttr_pipe=_saAttr_pipe,
                                      saAttr_file=_saAttr_file):
            """Create the named pipe and the file for it.

            :param prefix: string representing the prefix which will be
                appended to the start of the name for the pipe
            :param saAttr_pipe: security attributes used to create
                the named pipe
            :param saAttr_file: security attributes used to create the file
            """
            pipename = ("%s_NamedPipe_%d_%d_%s" % (
                prefix, pid, time.time(), str(random.random()).split(".")[1]))
            # Create the named pipe
            pipe = NamedPipe(pipe_name=pipename,
                             sec_attributes=saAttr_pipe)
            # Create the file for the previously created named pipe
            pipe.create_file(sec_attributes=saAttr_file)
            return pipe

        # Create the named pipes and the files used for parent - child process
        # communication.
        _pipe_stdin = create_namedpipe_and_file("Stdin")
        self._pipe_stdout = create_namedpipe_and_file("Stdout")
        self._pipe_stderr = create_namedpipe_and_file("Stderr")

        # Set the file handles from the named pipes as stdin, stdout and stderr
        # in startupinfo structure for the child process.
        self._si.hStdInput = _pipe_stdin.get_file_handle()
        self._si.hStdOutput = self._pipe_stdout.get_file_handle()
        self._si.hStdError = self._pipe_stderr.get_file_handle()
        self._si.dwFlags |= win32con.STARTF_USESTDHANDLES

        # Wrapping around stdin in order to be able to call self.stdin.close()
        # to close the stdin.
        self.stdin = ProcessWithNamedPipes.HandleClass(_pipe_stdin)
        _pipe_stdin = None

    def _get_result_namedpipe(self, namedpipe):
        """Retrieve the result from the named pipe given as parameter.

        This function will return False if the read operation has not
        completed yet and we should call this method again to try to retrieve
        the result.

        :param namedpipe: represents the NamedPipe object from where to
            retrieve the result
        """
        # The default returned value will be empty string. This is returned
        # in case the pipe was disconnected.
        output = ""
        try:
            output = namedpipe.get_read_result()
        except NamedPipeException as e:
            # If the pipe was disconnected the error is ignored, otherwise
            # we raise an exception
            if e.code not in ovs_winutils.pipe_disconnected_errors:
                raise e
        return output

    def communicate(self, input=None):
        """Return stdout and stderr of the child process.

        Interact with process: Send the 'input' argument to stdin.
        The function waits until the process terminates and reads from
        stdout and stderr.

        :param input: string representing the input which should be sent
            to the child process. If this value is None, then nothing is passed
            as stdin for the child process.
        """
        if input:
            # If we received any input, write it to stdin then close the handle
            # to send EOF on stdin to the child process
            self._stdin_write(input)
            self.stdin.close()

        # Try to retrieve the output for stdout and stderr. If the read
        # operation has not completed yet, then None will be returned and
        # we will try to retrieve the result again after the process is
        # terminated.
        stdout = self._pipe_stdout.nonblocking_read(self._BUFSIZE)
        stderr = self._pipe_stderr.nonblocking_read(self._BUFSIZE)

        # Wait for the process to terminate
        self.wait()

        if stdout is None:
            # Wait until the read operation for stdout has completed and
            # then retrieve the result.
            self._pipe_stdout.wait_for_read()
            stdout = self._get_result_namedpipe(self._pipe_stdout)

        if stderr is None:
            # Wait until the read operation for stdout has completed and
            # then retrieve the result.
            self._pipe_stderr.wait_for_read()
            stderr = self._get_result_namedpipe(self._pipe_stderr)

        # Close all the handles since the child process is terminated
        # at this point.
        self._pipe_stdout.close_all_handles()
        self._pipe_stdout = None
        self._pipe_stderr.close_all_handles()
        self._pipe_stderr = None

        # Return a tuple containing stdout and stderr to ensure compatibility
        # with the subprocess module.
        return (stdout, stderr)

    def _stdin_write(self, input):
        """Send input to stdin for the child process."""
        if input:
            encoded_buf = ovs_winutils.get_encoded_buffer(input)
            self.stdin.namedpipe.blocking_write(encoded_buf)

    def _start_process(self, cmd_line, env):
        """Create a process with the command line 'cmd_line' and environment
        'env'. Stores the pid of the child process in the 'pid' attribute.
        """
        app_name = None
        # The command line to be executed.
        command_line = cmd_line
        process_attributes = None
        thread_attributes = None
        # Each inheritable handle in the calling process is
        # inherited by the new process.
        inherit_handles = 1
        # The new process has a new console, instead of inheriting
        # its parent's console
        creation_flags = win32process.CREATE_NO_WINDOW
        # Environment used for the new process.
        new_environment = env
        current_directory = None

        proc_args = (app_name,
                     command_line,
                     process_attributes,
                     thread_attributes,
                     inherit_handles,
                     creation_flags,
                     new_environment,
                     current_directory,
                     self._si)
        proc_handles = win32process.CreateProcess(*proc_args)

        # Close the handles that the parent is not going to use
        self._pipe_stdout.close_filehandle()
        self._pipe_stderr.close_filehandle()

        self._hProcess, self._hThread, self.pid, self._tid = proc_handles

    def wait(self, timeout=None):
        """Wait for the process to terminate or until timeout expires.

        Returns returncode attribute. If timeout is None, then the method
        will wait until the process terminates.

        :param timeout: int or float representing the timeout in seconds
        """
        if timeout is None:
            timeout_millis = win32event.INFINITE
        else:
            timeout_millis = int(timeout * 1000)

        if self.returncode is None:
            # If the 'returncode' attribute is not set, it means that we
            # have to wait for the child process to terminate and to return the
            # exit code of it.
            result = avoid_blocking_call(win32event.WaitForSingleObject,
                                         self._hProcess,
                                         timeout_millis)
            if result == win32event.WAIT_TIMEOUT:
                raise ProcessException("Timeout Exception.")
            self.returncode = win32process.GetExitCodeProcess(self._hProcess)
        # Return the exit code of the child process
        return self.returncode
