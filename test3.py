#coding=utf-8
'''
Created on Feb 8, 2011

@author: vvitvitskiy
'''
from java.lang import Exception as JException
from java.lang import String
import netutils
import entity
import logger
import jee
from java.io import StringReader
from java.io import ByteArrayInputStream
import re
from file_topology import FileAttrs
import file_system
import file_topology
from javax.xml.parsers import DocumentBuilderFactory
from javax.xml.xpath import XPathFactory
from appilog.common.system.types.vectors import ObjectStateHolderVector
import jms
from com.hp.ucmdb.discovery.library.communication.downloader.cfgfiles import GeneralSettingsConfigFile
from org.jdom.input import SAXBuilder
from org.jdom import JDOMException


class ServerRuntime:
    def __init__(self, commandLineDescriptor, ip = None):
        '''
        @types: jee.JvmCommandLineDescriptor, str
        @raise ValueError: Empty command line descriptor
        @raise ValueError: IP is not valid
        '''
        self.__cmdDescriptor = commandLineDescriptor
        if ip is not None and not netutils.isValidIp(ip):
            raise ValueError("IP is not valid: %s" % ip)
        self.__ip = ip

    def getJvmInitialPermSize(self):
        pattern = r'-XX\:PermSize=(\d+)m'
        m = re.search(pattern, self.getCommandLine())
        return m and m.group(1)

    def getJvmMaxPermSize(self):
        pattern = r'-XX\:MaxPermSize=(\d+)m'
        m = re.search(pattern, self.getCommandLine())
        return m and m.group(1)

    def getJvmInitialHeapSize(self):
        pattern = r'-Xms(\d+)m'
        m = re.search(pattern, self.getCommandLine())
        return m and m.group(1)

    def getJvmMaxHeapSize(self):
        pattern = r'-Xmx(\d+)m'
        m = re.search(pattern, self.getCommandLine())
        return m and m.group(1)


    def getIp(self):
        '@types: -> str'
        return self.__ip

    def getCommandLine(self):
        '@types: -> str'
        return self.__cmdDescriptor.getCommandLine()

    def _getCommandLineDescriptor(self):
        '@types: -> jee.JvmCommandLineDescriptor'
        return self.__cmdDescriptor

    def findJavaCommandPath(self):
        '@types: -> str or None'
        javaCommandPattern = '(.*?java.*?)\s'
        matchObj = re.match(javaCommandPattern, self.getCommandLine())
        return matchObj and matchObj.group(1)

    def __repr__(self):
        return 'ServerRuntime("%s")' % self.__cmdDescriptor.getCommandLine()


class ApplicationResource(jee.Resource, entity.HasName):
    r'Web application resource'
    def __init__(self, name, resourceType, description = None):
        r'@types: str, str'
        entity.HasName.__init__(self, name)
        self.type = resourceType
        self.description = description


class _HasResources:
    r'''Application entries (servlets, beans) may refer to different resources with unique name
    Classes handles unique resources by their name
    '''
    def __init__(self):
        r'dict(src, ApplicationResource)'
        self.__resourceByName = {}

    def addResource(self, resource):
        r'@types: ApplicationResource'
        if resource is not None:
            self.__resourceByName.setdefault(resource.getName(), resource)

    def getResources(self):
        r'@types: -> ApplicationResource'
        return self.__resourceByName.values()


class BaseDescriptor(_HasResources):
    r'Base class for JEE descriptors'
    def __init__(self, displayName, description):
        _HasResources.__init__(self)
        self.displayName = displayName
        self.description = description


class ApplicationDescriptor(BaseDescriptor):
    r'Object model of META-INF/application.xml file content.'
    def __init__(self, displayName, description):
        BaseDescriptor.__init__(self, displayName, description)
        r'list(jee.EjbModule)'
        self.__ejbModules = []
        r'list(jee.WebModule)'
        self.__webModules = []

    def addEjbModules(self, *modules):
        r'@types: list(jee.EjbModule)'
        if modules:
            self.__ejbModules.extend(modules)

    def addWebModules(self, *modules):
        r'@types: list(jee.WebModule)'
        if modules:
            self.__webModules.extend(modules)

    def getEjbModules(self):
        r'@types: -> list(jee.EjbModule)'
        return self.__ejbModules[:]

    def getWebModules(self):
        r'@types: -> list(jee.WebModule)'
        return self.__webModules[:]


class WebModuleDescriptor(BaseDescriptor):
    r'Object model of WEB-INF/web.xml file content.'

    def __init__(self, displayName, description):
        BaseDescriptor.__init__(self, displayName, description)
        r'list(jee.Servlet)'
        self.__servlets = []

    def addServlets(self, *servlets):
        r'@types: list(jee.Servlet)'
        if servlets:
            self.__servlets.extend(servlets)

    def getServlets(self):
        r'@types: -> list(jee.Servlet)'
        return self.__servlets[:]


class EjbModuleDescriptor(BaseDescriptor):
    def __init__(self, displayName, description):
        BaseDescriptor.__init__(self, displayName, description)
        r'list(jee.EjbModule.Entry)'
        self.__beans = []

    def addBeans(self, *beans):
        r'@types: list(EjbModule.Entry)'
        if beans:
            self.__beans.extend(beans)

    def getBeans(self):
        r'@types: -> list(EjbModule.Entry)'
        return self.__beans[:]


class InvalidXmlException(Exception): pass
class BaseXmlParser:
    def __init__(self, loadExternalDtd = 1):
        r'@types: bool'
        self.__laodExternalDtd = loadExternalDtd

    def _buildDocument(self, content):
        r'''
        @types: str-> org.jdom.Document
        @raise ValueError: if content is None
        @raise InvalidXmlException: if content is not valid xml
        '''
        if not content:
            raise ValueError('Empty content')
        builder = SAXBuilder()
        builder.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", self.__laodExternalDtd)
        try:
            return builder.build(StringReader(content))
        except JDOMException, e:
            raise InvalidXmlException(e.getMessage())

    def _buildDocumentForXpath(self, content, namespaceAware = 1):
        if not content:
            raise ValueError('Empty content')
        xmlFact = DocumentBuilderFactory.newInstance()
        xmlFact.setNamespaceAware(namespaceAware)
        xmlFact.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", self.__laodExternalDtd)
        builder = xmlFact.newDocumentBuilder()
        try:
            return builder.parse(ByteArrayInputStream(String(content).getBytes()))
        except JException, e:
            raise InvalidXmlException(e.getMessage())


    def _getXpath(self):
        r'@types: -> javax.xml.xpath.XPath'
        return XPathFactory.newInstance().newXPath()

    def _getRootElement(self, content):
        r'''
        @types: str -> org.jdom.Element
        @raise ValueError: if content is None
        @raise InvalidXmlException: if content is not valid xml
        '''
        return self._buildDocument(content).getRootElement()

    def _stripped(self, obj):
        return obj and str(obj).strip()


class ApplicationDescriptorParser(BaseXmlParser):

    def __createDescriptor(self, descriptorClass, rootElement):
        r'@types: PyClass, org.jdom.Element -> PyClass Instance'
        displayName = rootElement.getChildText('display-name')
        description = rootElement.getChildText('description')
        return descriptorClass(self._stripped(displayName),
                               self._stripped(description))

    def parseApplicationDescriptor(self, content):
        r''' Parse application.xml file content - EAR application descriptor
        @types: str -> ApplicationDescriptor
        @resource-file: application.xml
        '''
        root = self._getRootElement(content)
        descriptor = self.__createDescriptor(ApplicationDescriptor, root)
        modulesElements = root.getChildren('module', root.getNamespace())
        it = modulesElements.iterator()
        while it.hasNext():
            moduleElement = it.next()
            moduleNs = moduleElement.getNamespace()
            webElement = moduleElement.getChild('web', moduleNs)
            if webElement:
                ns = webElement.getNamespace()
                module = jee.WebModule(webElement.getChildText('web-uri', ns))
                module.contextRoot = webElement.getChildText('context-root', ns)
                descriptor.addWebModules(module)
            else:
                ejbElement = moduleElement.getChild('ejb', moduleNs)
                if ejbElement:
                    module = jee.EjbModule(moduleElement.getChildText('ejb', moduleElement.getNamespace()))
                    descriptor.addEjbModules(module)
        logger.info("Application '%s' has %s web modules and %s ebj modules. Resources %s" % (
                       descriptor.displayName or '',
                       len(descriptor.getWebModules()),
                       len(descriptor.getEjbModules()),
                       len(descriptor.getResources()) ))
        return descriptor

    def parseWebApplicationDescriptor(self, content):
        r''' Parse web.xml file content - WAR application descriptor
        @types: str -> jee_discoverer.WebModuleDescriptor
        @resource-file: web.xml
        @deprecated: @see parseWebModuleDescriptor method as it has consistent naming according to functionality
        '''
        root = self._getRootElement(content)
        descriptor = self.__createDescriptor(WebModuleDescriptor, root)
        servletElmts = root.getChildren('servlet', root.getNamespace())
        itServlets = servletElmts.iterator()

        servletByName = {}
        # parse declared servlets
        while itServlets.hasNext():
            servletElement = itServlets.next()
            servletElementNs = servletElement.getNamespace()
            name = servletElement.getChildText('servlet-name', servletElementNs)
            description = servletElement.getChildText('description', servletElementNs)
            servlet = jee.Servlet(name, description = description)
            servlet.className = servletElement.getChildText('servlet-class', servletElementNs)
            descriptor.addServlets(servlet)

            servletByName[name] = servlet
        # parse declared resources
        for resource in self._parseResources(root):
            descriptor.addResource(resource)
        # parse url patterns for declared servlets using servlet-mapping elements
        servletMappingElements =root.getChildren('servlet-mapping', root.getNamespace())
        itServletMapping = servletMappingElements.iterator()
        while itServletMapping.hasNext():
            mappingElement = itServletMapping.next()
            mappingElementNs = mappingElement.getNamespace()
            name = mappingElement.getChildText('servlet-name', mappingElementNs)
            servlet = servletByName.get(name)
            if servlet is not None:
                urlPattern = mappingElement.getChildText('url-pattern', mappingElementNs)
                servlet.addUrlPatterns(urlPattern)
        logger.info("Web module '%s' has %s servlets. Resources %s"
                    % (descriptor.displayName or '',
                       len(descriptor.getServlets()),
                       len(descriptor.getResources()))
                    )
        return descriptor

    def parseWebModuleDescriptor(self, content):
        r''' Parse web.xml file content - WAR application descriptor
        @types: str -> jee_discoverer.WebModuleDescriptor
        @resource-file: web.xml
        '''
        return self.parseWebApplicationDescriptor(content)

    def parseEjbModuleDescriptor(self, content):
        r''' Parse ejb-jar.xml file content - EJB module descriptor
        @types: str -> jee_discoverer.EjbModuleDescriptor
        @resource-file: ejb-jar.xml
        '''
        root = self._getRootElement(content)
        descriptor = self.__createDescriptor(EjbModuleDescriptor, root)
        beansRoot = root.getChild('enterprise-beans', root.getNamespace())
        if beansRoot:
            beansRootNs = beansRoot.getNamespace()
            beansElements = beansRoot.getChildren('session', beansRootNs)
            it = beansElements.iterator()
            while it.hasNext():
                beanElement = it.next()
                beanElementNs = beanElement.getNamespace()
                name = beanElement.getChildText('ejb-name', beanElementNs)
                bean = self.__createSessionBean(beanElement, name, beanElementNs)
                bean.description = self._stripped(beanElement.getChildText('description', beanElementNs))
                descriptor.addBeans(bean)
                for resource in self._parseResources(beanElement):
                    descriptor.addResource(resource)

            beansElements = beansRoot.getChildren('entity', beansRootNs)
            it = beansElements.iterator()
            while it.hasNext():
                beanElement = it.next()
                beanElementNs = beanElement.getNamespace()
                bean = jee.EntityBean(beanElement.getChildText('ejb-name', beanElementNs))
                bean.description = self._stripped(beanElement.getChildText('description', beanElementNs))
                descriptor.addBeans(bean)
                for resource in self._parseResources(beanElement):
                    descriptor.addResource(resource)

            beansElements = beansRoot.getChildren('message-driven', beansRootNs)
            it = beansElements.iterator()
            while it.hasNext():
                beanElement = it.next()
                beanElementNs = beanElement.getNamespace()
                bean = jee.MessageDrivenBean(beanElement.getChildText('ejb-name', beanElementNs))
                bean.description = self._stripped(beanElement.getChildText('description', beanElementNs))
                descriptor.addBeans(bean)
                for resource in self._parseResources(beanElement):
                    descriptor.addResource(resource)
        logger.info('EJB module "%s" contains %s beans' %
                    (descriptor.displayName,
                     len(descriptor.getBeans())))
        return descriptor

    def _parseResources(self, element):
        r'@types: org.jdom.Element -> list(jee_discoverer.ApplicationResource)'
        resources = []
        resourceRefList = element.getChildren('resource-ref', element.getNamespace())
        if resourceRefList != None:
            it = resourceRefList.iterator()
            while it.hasNext():
                resourceRef = it.next()
                resourceRefNs = resourceRef.getNamespace()
                name = resourceRef.getChildText('res-ref-name', resourceRefNs)
                resourceType = resourceRef.getChildText('res-type', resourceRefNs)
                description = self._stripped(resourceRef.getChildText('description', resourceRefNs))
                resources.append( ApplicationResource(name, resourceType, description) )
        return resources

    def __createSessionBean(self, beanElement, name, beansElementsNs):
        '@types: org.jdom.Element, str, org.jdom.Namespace -> jee.EjbModule.Entry'
        specificClass = None
        sessionType = beanElement.getChildText('session-type', beansElementsNs)
        if sessionType:
            if sessionType.lower().count('stateless'):
                specificClass = jee.Stateless
            elif sessionType.lower().count('stateful'):
                specificClass = jee.Stateful
        else:
            specificClass = jee.SessionBean
        return specificClass(name)


class Layout:
    r'Abstract class for any type of layout'
    def __init__(self, fs):
        r'''@types: file_system.FileSystem
        @raise ValueError: Path manipulation approach is not specified
        '''
        self.__fs = fs
        pathUtil = file_system.getPath(fs)
        if not pathUtil:
            raise ValueError("Path manipulation approach is not specified")
        self.__pathUtil = pathUtil

    def _getFs(self):
        r'@types: -> file_system.FileSystem'
        return self.__fs

    def path(self):
        r'@types: -> file_topology.Path'
        return self.__pathUtil

    def getFile(self, path):
        r'@types: str -> file_topology.File'
        path = self.__pathUtil.normalizePath(path)
        return self.__fs.getFile(path, file_topology.BASE_FILE_ATTRIBUTES + [FileAttrs.CONTENT])

    def getFileContent(self, path):
        r'''@types: str -> file_topology.File
        @deprecated: Use getFile method instead
        '''
        path = self.__pathUtil.normalizePath(path)
        return self.__fs.getFile(path, [FileAttrs.CONTENT, FileAttrs.NAME, FileAttrs.PATH])


class ApplicationLayout(Layout):
    'Base layout to discovery application components. For instance - locating descriptor files'

    class XmlFileFilter(file_system.FileFilter):
        def accept(self, file):
            r'@types: file_topology.File -> bool'
            return file.path.endswith('.xml')

    def __init__(self, fs):
        r'@types: file_system.FileSystem'
        Layout.__init__(self, fs)

    def composeModulePathByEarPath(self, path, name):
        r'''
        @types: str, str -> str
        '''
        return self.path().join(path, name)

    def findEarDescriptorFiles(self, path):
        r'@types: str -> list(file_topology.File)'
        return self._findDescriptorFilesIn( self.path().join(path, 'META-INF') )

    def findWebDescriptorFiles(self, path):
        r'@types: str -> list(file_topology.File)'
        return self._findDescriptorFilesIn( self.path().join(path, 'WEB-INF') )

    def _findDescriptorFilesIn(self, path):
        r'@types: str -> list(file_topology.File)'
        return self._getFs().getFiles(path,
                filters = [self.XmlFileFilter()],
                fileAttrs = [file_topology.FileAttrs.PATH, file_topology.FileAttrs.NAME])


class HasJmxProvider:
    'Base JEE platform discoverer by JMX'
    def __init__(self, provider):
        '@types: jmx.Provider'
        self.__provider = provider

    def _getProvider(self):
        '@types: -> jmx.Provider'
        return self.__provider


class DiscovererByShell:
    'Base JEE platform discoverer by Shell'
    def __init__(self, shell, layout):
        '''@types: shellutils.Shell, ServerLayout
        @raise ValueError: Processor is not set'''
        self.__layout = layout
        self.__shell = shell

    def getLayout(self): return self.__layout

    def _getShell(self): return self.__shell

def _quotePathIfHasSpaces(path):
    '@deprecated: USE layout methods instead'
    if path.find(' ') != -1:
        if path[0] != '"':
            path = '"' + path
        if path[len(path) -1 ] != '"':
            path = path + '"'
    return path


class JvmDiscovererByShell(DiscovererByShell):

    def __init__(self, shell, layout):
        r'@types: shellutils.Shell, jee_discoverer.Layout'
        DiscovererByShell.__init__(self, shell, layout)

    def discoverJvmByServerRuntime(self, serverRuntime):
        '@types: jee_discoverer.ServerRuntime -> jee.Jvm'
        jvm = jee.Jvm('jvm')
        javaPath = serverRuntime.findJavaCommandPath()
        try:
            if javaPath:
                jvm = self.getJVMInfo(_quotePathIfHasSpaces(javaPath))
        except:
            logger.warnException('Failed to get JVM information')
#        Need to expand if the path is only 'java' or else like that
#        if javaPath:
#            jvm.resourcePath = javaPath
        initialPermSize = serverRuntime.getJvmInitialPermSize()
        if initialPermSize:
            jvm.initialPermSizeInBytes.set(1024*1024*long(initialPermSize))

        maxPermSize = serverRuntime.getJvmMaxPermSize()
        if maxPermSize:
            jvm.maxPermSizeInBytes.set(1024*1024* long(maxPermSize))

        initialHeapSize = serverRuntime.getJvmInitialHeapSize()
        if initialHeapSize:
            jvm.initialHeapSizeInBytes.set(1024*1024*long(initialHeapSize))

        maxHeapSize = serverRuntime.getJvmMaxHeapSize()
        if maxHeapSize:
            jvm.maxHeapSizeInBytes.set(1024*1024*long(maxHeapSize))

        jvm.osVersion = str(self._getShell().getOsVersion()).strip()
        jvm.osType = self._getShell().getOsType()
        return jvm

    def getJVMInfo(self, javaCommand):
        ''' Get JVM info (version, vendor)
        @types: str -> jee.Jvm
        @command: java -version
        @raise Exception: Failed to get JVM information
        '''
        # "java.exe -version" command prints its output always to standard error stream,
        # instead of standard output.
        # This causes the result to be discarded.
        # A simple workaround is to redirect the output to standard output stream,
        # this can be done by sending the following command: "java.exe -version 2>&1"
        javaCommand = '%s -version 2>&1' % javaCommand
        output = self._getShell().execCmd(javaCommand)
        if self._getShell().getLastCmdReturnCode() != 0:
            raise Exception( "Failed to get JVM information. %s" % output)

        name = None
        vendor = None
        javaVersion = None
        for line in output.strip().split('\n'):
            matchObj = re.search('java version \"(.+?)\"', line)
            if matchObj:
                javaVersion = matchObj.group(1)
            #cover lines:
            #Java(TM) 2 Runtime Environment, Standard Edition (build 1.4.2)
            #Java(TM) SE Runtime Environment..
            elif re.match(r'Java\(TM\) .+ Runtime Environment', line):
                name = line.strip()
            else:
                vendor = 'Sun Microsystems Inc.'
                if line.lower().find('bea') == 0:
                    vendor = 'BEA'
                elif line.lower().find('ibm') == 0:
                    vendor = 'IBM Corporation'

        jvm = jee.Jvm(name or 'jvm')
        jvm.javaVersion = javaVersion
        jvm.javaVendor = vendor
        return jvm


class BaseApplicationDiscoverer:

    def __init__(self, descriptorParser):
        r'@types: ApplicationDescriptorParser'
        if not descriptorParser:
            raise ValueError("Descriptor parser is not specified")
        self.__descriptorParser = descriptorParser

    def _getDescriptorParser(self):
        return self.__descriptorParser

    def _splitDescriptorFilesByType(self, files, *jeeDescriptorFileNames):
        r'@types: list(file_topology.File), tuple(str) -> tuple(list(file_topology.File), list(file_topology.File))'
        jeeDescriptorFiles = []
        runtimeDescriptorFiles = []
        for file in files:
            if file.name in jeeDescriptorFileNames:
                jeeDescriptorFiles.append( file )
            else:
                runtimeDescriptorFiles.append( file )
        return (jeeDescriptorFiles, runtimeDescriptorFiles)


class BaseApplicationDiscovererByShell(BaseApplicationDiscoverer, DiscovererByShell):
    def __init__(self, shell, layout, descriptorParser):
        r'''@types: shellutils.Shell, ServerLayout, ApplicationDescriptorParser
        @raise ValueError: Descriptor parser is not specified
        '''
        BaseApplicationDiscoverer.__init__(self, descriptorParser)
        DiscovererByShell.__init__(self, shell, layout)

    def discoverEarApplication(self, name, path):
        r'@types: str, str -> jee.Application or None'
        application = jee.EarApplication(name, path)
        try:
            logger.info("Find EAR descriptor files for '%s'" % name)
            path = self.getLayout().path().normalizePath(path)
            files = self.getLayout().findEarDescriptorFiles(path)
        except (Exception, JException), exc:
            logger.warn("Failed to find descriptor files for enterprise application. %s" % exc)
        else:
            jeeDescriptors, runtimeDescriptors = self._splitDescriptorFilesByType(files, 'application.xml')
            if jeeDescriptors:
                try:
                    logger.info("Get JEE deployment descriptor content")
                    file = self.getLayout().getFileContent(jeeDescriptors[0].path)
                    descriptor = self._getDescriptorParser().parseApplicationDescriptor(file.content)
                except (Exception, JException), exc:
                    logger.warnException("Failed to parse application.xml. %s" % exc)
                else:
                    application.addConfigFiles(jee.createXmlConfigFile(file))
                    # discover details about WEB modules if they are unpacked
                    # web modules after deploy are unpacked in the EAR folder
                    # as contain static data accessible by the web container
                    for module in descriptor.getWebModules():
                        webModule = module
                        modulePath = self.getLayout().composeModulePathByEarPath(path, module.getName())
                        try:
                            webModule = self._findWebModule(module.getName(), modulePath)
                        except file_system.PathNotFoundException, e:
                            logger.warn("Failed to get web module descriptor. %s" % e)
                        except (Exception, JException), e:
                            logger.warnException("Failed to find descriptor files for web application. %s" % e)
                        if module.contextRoot:
                            webModule.contextRoot = module.contextRoot
                        application.addModules(webModule)
                    # EJB modules are not unpacked in EAR
                    application.addModules(* descriptor.getEjbModules())
                for file in runtimeDescriptors:
                    try:
                        fileWithContent = self.getLayout().getFileContent(file.path)
                        application.addConfigFiles(jee.createXmlConfigFile(fileWithContent))
                    except (Exception, JException), exc:
                        logger.warnException("Failed to load content for runtime descriptor: %s" % file.name)
        return application

    def discoverWarApplication(self, name, path):
        r'@types: str, str -> jee.WarApplication or None'
        application = None
        try:
            webModule = self._findWebModule(name, path)
        except file_system.PathNotFoundException, e:
            logger.warn("Failed to get web module descriptor. %s" % e)
        except Exception:
            logger.warn('Failed to find web module by name %s in path %s' % (name, path))
        else:
            application = jee.WarApplication(name, path)
            application.addModules(webModule)
        return application

    def _findWebModule(self, name, path):
        r''' Module detected by presence of file 'WEB-INF/web.xml' in specified path
        @types: str, str -> jee.WebModule
        @raise ValueError: JEE descriptor is not found
        '''
        webModule = jee.WebModule(name)

        logger.info("Find WAR descriptor files for '%s'" % name)
        path = self.getLayout().path().normalizePath(path)
        files = self.getLayout().findWebDescriptorFiles(path)

        # split descriptors by type - jee or runtime
        jeeDescriptors, runtimeDescriptors = self._splitDescriptorFilesByType(files, 'web.xml')
        if jeeDescriptors:
            try:
                logger.info('Get WEB deployment descriptor content')
                file = self.getLayout().getFileContent(jeeDescriptors[0].path)
                webModule.addConfigFiles(jee.createXmlConfigFile(file))
                descriptor = self._getDescriptorParser().parseWebApplicationDescriptor(file.content)
                for servlet in descriptor.getServlets():
                    webModule.addEntry(servlet)
            except (Exception, JException):
                logger.warnException("Failed to process web.xml")
            # process runtime descriptor files
            for file in runtimeDescriptors:
                try:
                    fileWithContent = self.getLayout().getFileContent(file.path)
                    webModule.addConfigFiles(jee.createXmlConfigFile(fileWithContent))
                except (Exception, JException):
                    logger.warnException("Failed to load content for runtime descriptor: %s" % file.name)
        else:
            raise ValueError("JEE descriptor is not found")
        return webModule

def discoverDomainTopology(connectionPort, connectionIpAddress, domain, dnsResolver, credentialsfulServerRole, roleWithPortClass, reporter, setDomainIp = 1):
    r'@types: int, str, jee.Domain, netutils.BaseDnsResolver, jee.HasCredentialInfoRole, PyClass, jee.ServerTopologyReporter, bool -> ObjectStateHolderVector'
    # make discovery itself
    if not domain:
        raise ValueError("Failed to discover available domain")
    # We cannot report domain without servers - need to track
    # presence of attached server with resolved IP address
    domainHasAtLeastOneServerWithResolvedAddress = 0
    # check whether domain has only one node and one server in it
    # it is attribute of stand-alone installation
    if len(domain.getNodes()) == 1 and len(domain.getNodes()[0].getServers()) == 1:
        server = domain.getNodes()[0].getServers()[0]
        role = server.getRole(roleWithPortClass)
        if role and not role.getPort():
            role.setPort(connectionPort)
        server.addDefaultRole(credentialsfulServerRole)
        server.ip.set(connectionIpAddress)
        domainHasAtLeastOneServerWithResolvedAddress = 1

    # in this case we have more then one server in domain
    for node in domain.getNodes():
        for server in node.getServers():
            try:
                # make IP address resolving
                if server.ip.value():
                    domainHasAtLeastOneServerWithResolvedAddress = 1
                elif server.hostname:
                    ips = dnsResolver.resolveIpsByHostname(server.hostname)
                    if ips:
                        server.ip.set(ips[0])
                        domainHasAtLeastOneServerWithResolvedAddress = 1

            except (Exception, JException), exc:
                logger.warn(str(exc))
            else:
                if not server.hasRole(credentialsfulServerRole.__class__):
                    # find server that we are connected to
                    # need to apply role with credentials information
                    # by two criteria:
                    # -port
                    fitsPortCriteria = 0
                    for role in server.getRolesByBase(entity.HasPort):
                        if role.getPort() == connectionPort:
                            fitsPortCriteria = 1
                    # -IP address
                    fitsIpAddressCriteria = (server.ip.value() == connectionIpAddress)
                    if fitsPortCriteria and fitsIpAddressCriteria:
                        server.addRole(credentialsfulServerRole)

                # find out administrative IP address for the domain
                if setDomainIp and server.hasRole(jee.AdminServerRole):
                    domain.setIp(server.ip.value())

    if not domainHasAtLeastOneServerWithResolvedAddress:
        raise ValueError("There is no at least one server with resolved IP address")
    # do not send domain if administrative IP is unknown
    vector = ObjectStateHolderVector()
    if domain.getIp() or not setDomainIp:
        vector.addAll( reporter.reportNodesInDomain(domain, *domain.getNodes()) )
    else:
        for node in domain.getNodes():
            vector.addAll( reporter.reportServers( node.getServers() ) )
    return vector

def getPlatformTrait(versionInfo, platform, fallbackVersion = None):
    '''@types: str, jee.Platform, number -> entity.PlatformTrait
    @param fallbackVersion: Fallback parameter if version in provided info cannot be recognized
    @raise ValueError: Product version cannot be recognized
    '''
    matchObj = re.match('.*?(\d+)(?:\.(\d+))?.*?', str(versionInfo))
    if matchObj:
        major, minor = matchObj.groups()
        trait = entity.PlatformTrait(platform, major, minor)
        logger.info("Found %s product with version: %s" % (platform, major))
    elif fallbackVersion:
        trait = entity.PlatformTrait(platform, fallbackVersion)
        logger.warn("Cannot recognize product version by provided information '%s'. Fallback to %sth " % (versionInfo, fallbackVersion))
    else:
        raise ValueError("Cannot resolve product version in '%s'" % versionInfo)
    return trait

def createDatasources(*applicationResources):
    r'@types: tuple(jee_discoverer.ApplicationResource) -> list(jee.Datasource)'
    datasources = []
    for resource in applicationResources:
        resourceType = resource.type
        if resourceType and resourceType == 'javax.sql.DataSource':
            datasources.append(jee.Datasource(resource.getName()))
    return datasources

class ReporterFactory:
    r'''Holds information about correct reporters'''
    def __init__(self, domainReporter, applicationReporter,
                 jdbcDatasourceReporter, jmsDatasourceReporter
        ):
        r'''
        @types: jee.ServerTopologyReporter, jee.ApplicationTopologyReporter, jee.DatasourceTopologyReporter, jms.TopologyReporter
        '''
        assert (domainReporter and applicationReporter
                and jdbcDatasourceReporter and jmsDatasourceReporter)
        self.__domainReporter = domainReporter
        self.__applicationReporter = applicationReporter
        self.__jdbcDatasourceReporter = jdbcDatasourceReporter
        self.__jmsDatasourceReporter = jmsDatasourceReporter

    def getDomainReporter(self): return self.__domainReporter
    def getApplicationReporter(self): return self.__applicationReporter
    def getJdbcDsReporter(self): return self.__jdbcDatasourceReporter
    def getJmsDsReporter(self): return self.__jmsDatasourceReporter

def isJeeEnhancedTopologyEnabled():
    globalSettings = GeneralSettingsConfigFile.getInstance()
    return globalSettings.getPropertyBooleanValue('enableJeeEnhancedTopology', 0)

def createTopologyReporterFactory(domainTopologyBuilder, dnsResolver):
    r''' Factory method to get proper topology reporters creator depending on
    passed flag
    @types: jee.ServerTopologyBuilder, netutils.BaseDnsResolver -> ReporterFactory'''

    if isJeeEnhancedTopologyEnabled():
        return ReporterFactory(
                jee.ServerEnhancedTopologyReporter(domainTopologyBuilder),
                jee.ApplicationEnhancedTopologyReporter(jee.ApplicationTopologyBuilder()),
                jee.EnhancedDatasourceTopologyReporter(jee.DatasourceTopologyBuilder(), dnsResolver),
                createDnsEnabledJmsTopologyReporter( jms.EnhancedTopologyReporter,
                                                     jms.TopologyBuilder(),
                                                     dnsResolver)
        )
    else:
        return ReporterFactory(
                jee.ServerTopologyReporter(domainTopologyBuilder),
                jee.ApplicationTopologyReporter(jee.ApplicationTopologyBuilder()),
                jee.DatasourceTopologyReporter(jee.DatasourceTopologyBuilder(), dnsResolver),
                createDnsEnabledJmsTopologyReporter(
                                                    jms.TopologyReporter,
                                                    jms.TopologyBuilder(),
                                                    dnsResolver)
        )


def createDnsEnabledJmsTopologyReporter(clazz, builder, dnsResolver):
    r''' Creates decorator class for the jms.TopologyReporter to add IP address
    resolving possibility for the destination servers

    @types: PyClass[jms.TopologyReporter], jms.TopologyBuilder, netutils.BaseDnsResolver
    '''
    class DnsEnabledReporter(clazz):
        def __init__(self, topologyBuilder, dnsResolver):
            r'PyClass[jms.TopologyReporter], netutils.BaseDnsResolver'
            self.__baseClass = self.__class__.__bases__[0]
            self.__baseClass.__init__(self, topologyBuilder)
            self.__dnsResolver = dnsResolver

        def reportDatasourceWithDeployer(self, domain, deploymentScope, datasource):
            for destination in datasource.getDestinations():
                server = destination.server
                # we will resolve only non-empty not-IP addresses

                if server and server.address:
                    if not netutils.isValidIp(server.address):
                        try:
                            ips = self.__dnsResolver.resolveIpsByHostname(server.address)
                        except (Exception, JException), e:
                            logger.warn(str(e))
                        else:
                            server.address = ips[0]
            return self.__baseClass.reportDatasourceWithDeployer(self, domain, deploymentScope, datasource)
    return DnsEnabledReporter(builder, dnsResolver)


class DnsResolverDecorator:
    r''' Decorates IP resolving by replacing local IP address with destination
    IP address
    '''
    def __init__(self, dnsResolver, destinationIpAddress):
        r'@types: netutils.BaseDnsResolver, str'
        assert (dnsResolver and destinationIpAddress
                and not netutils.isLocalIp(destinationIpAddress))
        self.__dnsResolver = dnsResolver
        self.__destinationIpAddress = destinationIpAddress

    def resolveIpsByHostname(self, hostname):
        ''' Process cases with loopback address (local IP)
        - when hostname is 'localhost' destination Ip address will be returned
        - resolved local IP address will be replaced by destination IP
        @types: str -> list[str]
        @raise ResolveException: Failed to resolve IP
        '''
        if hostname == 'localhost':
            return [self.__destinationIpAddress]
        ips = self.__dnsResolver.resolveIpsByHostname(hostname)
        isNotLocalIp = lambda ip: not netutils.isLocalIp(ip)
        nonLocalIps = filter(isNotLocalIp, ips)
        if len(nonLocalIps) < len(ips):
            # seems like we have local IPs
            nonLocalIps.append(self.__destinationIpAddress)
            ips = nonLocalIps
        return ips

    def __getattr__(self, name):
        return getattr(self.__dnsResolver, name)
