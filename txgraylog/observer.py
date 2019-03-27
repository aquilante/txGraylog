# Copyright (c) 2015 Adam Drakeford <adamdrakeford@gmail.com>
# See LICENSE for more details

"""
.. module:: observer
    :platform: Unix, Windows
    :synopsis: The observer for which our protocols to use
.. moduleauthor:: Adam Drakeford <adamdrakeford@gmail.com>
"""
from twisted.logger import LogLevel, globalLogPublisher
from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol, Protocol

from txgraylog.protocol.tcp import TCPGraylogFactory


class GraylogObserver:
    """ Graylog observer
    """

    def __init__(self, protocol, host, port, log_level=LogLevel.debug):
        self.protocol = protocol(host, port)
        self._log_level = log_level

        if issubclass(self.protocol.__class__, DatagramProtocol):
            reactor.listenUDP(0, self.protocol)
        elif issubclass(self.protocol.__class__, Protocol):
            reactor.connectTCP(
                self.protocol.host,
                self.protocol.port,
                TCPGraylogFactory(self.protocol)
            )
        else:
            raise ValueError('Incompatible protocol')

    def emit(self, event_dict):
        if 'log_level' in event_dict and \
           event_dict['log_level']._index >= self._log_level._index:
            self.protocol.log_message(event_dict)

    def start(self, with_reactor=False):
        if with_reactor:
            reactor.callWhenRunning(globalLogPublisher.addObserver, self.emit)
        else:
            globalLogPublisher.addObserver(self.emit)

    def stop(self):
        globalLogPublisher.removeObserver(self.emit)
