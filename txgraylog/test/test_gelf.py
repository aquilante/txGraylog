# Copyright (c) 2015 Adam Drakeford <adamdrakeford@gmail.com>
# See LICENSE for more details

"""
Tests for :class: `~txgraylog.gelf.GelfProtocol`
"""
import time
import jsonlib as json
import zlib
import struct
import binascii

from twisted.trial import unittest
from twisted.python import failure, randbytes

from txgraylog.protocol.gelf import GelfProtocol


class TestGELF(unittest.TestCase):
    """ Test our conversion between event dictionaries and GELF messages
    """

    def test_standard_log(self):
        """ Test a standard event dictionary that would be passed in by Twisted
        """
        t = time.time()
        g = GelfProtocol('localhost', **{
            'system': 'protocol',
            'log_format': 'this is a log message\nwhich could be continued',
            'isError': False,
            'version': '1.0',
            'time': t
        })

        self.assertEquals(len(g.generate()), 1)

        params = json.read(zlib.decompress(g.generate()[0]), use_float=True)

        self.assertEquals(params['facility'], 'protocol')
        self.assertEquals(params['short_message'], 'this is a log message')
        self.assertEquals(
            params['full_message'],
            '\n'.join(['this is a log message','which could be continued'])
        )
        self.assertEquals(params['level'], 6)
        self.assertEquals(params['version'], '1.0')
        self.assertEquals(params['timestamp'], t)

    def test_standard_log_iter(self):
        """ Test a standard event dictionary that would be passed in by Twisted
            using iter
        """
        t = time.time()
        g = GelfProtocol('localhost', **{
            'system': 'protocol',
            'log_format': 'this is a log message\nwhich could be continued',
            'isError': False,
            'version': '1.0',
            'time': t
        })

        for message in g:
            params = json.read(zlib.decompress(g.generate()[0]), use_float=True)

            self.assertEquals(params['facility'], 'protocol')
            self.assertEquals(params['short_message'], 'this is a log message')
            self.assertEquals(
                params['full_message'],
                '\n'.join(['this is a log message','which could be continued'])
            )
            self.assertEquals(params['level'], 6)
            self.assertEquals(params['version'], '1.0')
            self.assertEquals(params['timestamp'], t)

    def test_extended_paramaters(self):
        """ Test a log message with arbitrary parameters
        """

        g = GelfProtocol('localhost', **{
            'system': 'protocol',
            'message': ['this is a log message'],
            'isError': False,
            'time': time.time(),
            'username': 'foo',
            'bar': 'baz'
        })

        params = json.read(zlib.decompress(g.generate()[0]), use_float=True)

        self.assertEquals(params['_username'], 'foo')
        self.assertEquals(params['_bar'], 'baz')

    def test_error_log(self):
        """ Test an error log
        """

        f = failure.Failure(Exception('foo'))
        g = GelfProtocol('localhost', **{
            'system': 'protocol',
            'failure': f,
            'isError': True,
            'time': time.time(),
        })

        params = json.read(zlib.decompress(g.generate()[0]), use_float=True)

        self.assertEquals(params['level'], 3)
        self.assertEquals(params['short_message'], 'foo')
        self.failUnless('Traceback' in params['full_message'])

    def test_chunking_legacy_wan_size(self):
        """ Test the chunking of GELF messages
        """

        longMessage = binascii.hexlify(
            randbytes.insecureRandom(3000)) + b'more!'

        g = GelfProtocol('localhost', **{
            'system': 'protocol',
            'isError': False,
            'log_format': longMessage,
            'time': time.time(),
        })

        messages = g.generate()

        self.failUnless(len(messages) > 1)
        self.failUnless(messages[0].startswith(b'\x1e\x0f'))

        old_id = None
        for i in range(len(messages)):
            magic, chunk_id, seq, num_chunks = struct.unpack(
                b'>2s32sHH', messages[i][:38]
            )

            self.assertEquals(magic, b'\x1e\x0f')
            self.assertEquals(seq, i)
            self.assertEquals(num_chunks, len(messages))

            if old_id:
                self.assertEquals(chunk_id, old_id)

            old_id = chunk_id

    def test_chunking_legacy_lan_size(self):
        """ Test the chunking of GELF messages
        """
        from txgraylog.protocol.gelf import LAN_CHUNK

        longMessage = binascii.hexlify(
            randbytes.insecureRandom(9000)) + b'more!'

        g = GelfProtocol('localhost', size=LAN_CHUNK, **{
            'system': 'protocol',
            'isError': False,
            'log_format': longMessage,
            'time': time.time(),
        })

        messages = g.generate()

        self.failUnless(len(messages) > 1)
        self.failUnless(messages[0].startswith(b'\x1e\x0f'))

        old_id = None
        for i in range(len(messages)):
            magic, chunk_id, seq, num_chunks = struct.unpack(
                b'>2s32sHH', messages[i][:38]
            )

            self.assertEquals(magic, b'\x1e\x0f')
            self.assertEquals(seq, i)
            self.assertEquals(num_chunks, len(messages))

            if old_id:
                self.assertEquals(chunk_id, old_id)

            old_id = chunk_id

    def test_chunking_new_wan_size(self):
        """ Test the chunking of GELF messages
        """
        from txgraylog.protocol.gelf import GELF_NEW

        longMessage = binascii.hexlify(
            randbytes.insecureRandom(3000)) + b'more!'

        g = GelfProtocol('host', gelf_fmt=GELF_NEW, **{
                'system': 'protocol',
                'isError': False,
                'log_format': longMessage,
                'time': time.time(),
        })

        messages = g.generate()

        self.failUnless(len(messages) > 1)
        self.failUnless(messages[0].startswith(b'\x1e\x0f'))

        old_id = None
        for i in range(len(messages)):
            magic, chunk_id, seq, num_chunks = struct.unpack(
                b'2s8sBB', messages[i][:12]
            )

            self.assertEquals(magic, b'\x1e\x0f')
            self.assertEquals(seq, i)
            self.assertEquals(num_chunks, len(messages))

            if old_id:
                self.assertEquals(chunk_id, old_id)

            old_id = chunk_id

    def test_chunking_new_lan_size(self):
        """ Test the chunking of GELF messages
        """
        from txgraylog.protocol.gelf import GELF_NEW, LAN_CHUNK

        longMessage = binascii.hexlify(
            randbytes.insecureRandom(9000)) + b'more!'

        data = {
            'system': 'protocol',
            'isError': False,
            'log_format': longMessage,
            'time': time.time()
        }

        messages = GelfProtocol(
            'host', gelf_fmt=GELF_NEW, size=LAN_CHUNK, **data
        ).generate()

        self.failUnless(len(messages) > 1)
        self.failUnless(messages[0].startswith(b'\x1e\x0f'))

        old_id = None
        for i in range(len(messages)):
            magic, chunk_id, seq, num_chunks = struct.unpack(
                b'2s8sBB', messages[i][:12]
            )

            self.assertEquals(magic, b'\x1e\x0f')
            self.assertEquals(seq, i)
            self.assertEquals(num_chunks, len(messages))

            if old_id:
                self.assertEquals(chunk_id, old_id)

            old_id = chunk_id

    def test_chunking_iter(self):
        """ Test the chunking of GELF messages using iter
        """

        longMessage = binascii.hexlify(
            randbytes.insecureRandom(6000)) + b'more!'

        g = GelfProtocol('localhost', **{
            'system': 'protocol',
            'isError': False,
            'log_format': longMessage,
            'time': time.time(),
        })

        for index, message in enumerate(g):
            self.failUnless(message.startswith(b'\x1e\x0f'))

            old_id = None
            magic, chunk_id, seq, num_chunks = struct.unpack(
                '>2s32sHH', message[:38]
            )

            self.assertEquals(magic, b'\x1e\x0f')
            self.assertEquals(seq, index)

            if old_id:
                self.assertEquals(chunk_id, old_id)

            old_id = chunk_id
