#include <ndn-cxx/face.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <iostream>
#include <chrono>
#include <ndn-cxx/util/sha256.hpp>
#include <ndn-cxx/encoding/tlv.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <boost/asio.hpp>
#include <sstream>
#include "getFileName.cpp"
#include "nd-packet-format.h"
#include "nfdc-helpers.h"

/////////////////////////////////////////////
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
/////////////////////////////////////////////
using namespace ndn;
using namespace ndn::ndnd;
using namespace std;
namespace po = boost::program_options;
static void
usage(std::ostream& os, const po::options_description& options)
{
  os << "Usage: Named Data Neighbor Discovery (NDND) Client\n"
        "\n"
     << options;
}
class Options
{
public:
  Options()
    : m_prefix("/test/Ubuntu/client00")
    , server_prefix("/ndn/nd")
    , m_advertise_prefix("/local/advertise")
    , server_ip("192.168.29.145")
  {
  }
public:
  ndn::Name m_prefix;
  ndn::Name m_advertise_prefix;
  ndn::Name server_prefix;
  string server_ip;
};


class NDNDClient{
public:
  NDNDClient(const Name& m_prefix, 
            const Name& m_advertise_prefix,
             const Name& server_prefix, 
             const string& server_ip)
    : m_prefix(m_prefix)
    , m_advertise_prefix(m_advertise_prefix)
    , m_server_prefix(server_prefix)
  {
    m_scheduler = new Scheduler(m_face.getIoService());
    is_ready = false;
    setIP();
    m_port = htons(6363); // default
    inet_aton(server_ip.c_str(), &m_server_IP);

    // Bootstrap face and route to server
    std::string uri = "udp4://";
    uri += inet_ntoa(m_server_IP);
    uri += ':';
    uri += to_string(6363);
    addFace(uri, true);
  }

  // TODO: remove face on SIGINT, SIGTERM

  void registerRoute(const Name& route_name, int face_id,
                     int cost = 0, bool is_server_route = false) 
  {
   
    Interest interest = prepareRibRegisterInterest(route_name, face_id, m_keyChain, cost);
    m_face.expressInterest(
      interest,
      bind(&NDNDClient::onRegisterRouteDataReply, this, _1, _2, is_server_route),
      bind(&NDNDClient::onNack, this, _1, _2),
      bind(&NDNDClient::onTimeout, this, _1));
  }

  void onSubInterest(const Interest& subInterest)
  {
    // reply data with IP confirmation
    Buffer contentBuf;
    for (int i = 0; i < sizeof(m_IP); i++) {
      contentBuf.push_back(*((uint8_t*)&m_IP + i));
    }

    auto data = make_shared<Data>(subInterest.getName());
    if (contentBuf.size() > 0) {
      data->setContent(contentBuf.get<uint8_t>(), contentBuf.size());
    }
    else {
      return;
    }

    m_keyChain.sign(*data, security::SigningInfo(security::SigningInfo::SIGNER_TYPE_SHA256));
    // security::SigningInfo signInfo(security::SigningInfo::SIGNER_TYPE_ID, m_options.identity);
    // m_keyChain.sign(*m_data, signInfo);
    data->setFreshnessPeriod(time::milliseconds(4000));
    m_face.put(*data);
    cout << "NDND (Client): Publishing my ip: " << inet_ntoa(m_IP)<< endl;
  }
  ////////////////////////////////////////////////////////////////
   void onAdvertiseInterest(const Interest& interest)
  {
    if (!is_ready)
      return;
      //TODO: get add name to m_name details
    std::cout<<"get stripped advertise interest Name"<<interest.getName()<<std::endl;
    
    ndn::Name name = interest.getName();
    //qianzhuiming
    int k = m_advertise_prefix.size();
    while(k>0){
      name.erase(0);
      k-=1;
    }
    Name::Component component = name.get(0);
    int ret = component.compare(Name::Component("leave"));
    if (ret == 0)
    {
      //TODO delete prefix from m_name
      name.erase(0);
      m_chatinfo.remove(name);
    std::cout<<"delete"<<name<<std::endl;
    }
    else{
    std::cout<<"get stripped advertise interest Name"<<name<<std::endl;
    m_chatinfo.push_back(name);
    }
  }
  ////////////////////////////////////////////////////////////////////////////////////////////


  void sendArrivalInterest()
  {
    if (!is_ready) {
      std::cout << "NDND (Client): not ready, try again in 1 mins" << std::endl;
      m_scheduler->schedule(time::seconds(60), [this] {
          sendArrivalInterest();
      });
      return;
    }
    Name name("/ndn/nd/arrival");
    name.append((uint8_t*)&m_IP, sizeof(m_IP)).append((uint8_t*)&m_port, sizeof(m_port));
    name.appendNumber(m_prefix.size()).append(m_prefix).appendTimestamp();

    Interest interest(name);
    interest.setInterestLifetime(30_s);
    interest.setMustBeFresh(true);
    interest.setNonce(4);
    interest.setCanBePrefix(false); 

    cout << "NDND (Client):Sending Arrival Interest: " << interest << endl;

    m_face.expressInterest(interest, nullptr, bind(&NDNDClient::onNack, this, _1, _2), //no expectation
                           nullptr); //no expectation
  }
  //Autoomatically Sync chat info
  void syncChatInfo(){
    if (!is_ready) {
      std::cout << "NDND (Client): not ready, try again in 1 mins" << std::endl;
      m_scheduler->schedule(time::seconds(60), [this] {
          syncChatInfo();
      });
      return;
    }
    std::list<ndn::Name>chat_infos = m_chatinfo;
    for (auto name = chat_infos.begin();name!=chat_infos.end();name++){
          sendNewPrefixInterest(*name);
        }
    
  }

void sendNewPrefixInterest(ndn::Name prefix)
  {
    Name name("/ndn/nd/prefix");
    name.append((uint8_t*)&m_IP, sizeof(m_IP)).append((uint8_t*)&m_port, sizeof(m_port));
    name.appendNumber(prefix.size()).append(prefix).appendTimestamp();

    Interest interest(name);
    interest.setInterestLifetime(30_s);
    interest.setMustBeFresh(true);
    interest.setNonce(4);
    interest.setCanBePrefix(false); 

    cout << "NDND (Client-new prefix): Sending new prefix Interest: " << interest << endl;

    m_face.expressInterest(interest, nullptr, bind(&NDNDClient::onNack, this, _1, _2), //no expectation
                           nullptr); //no expectation
  }
  ///Automatically Sync file name with server TODO:Filter local NFD
  void syncFileName(){
          if (!is_ready) {
      std::cout << "NDND (Client): not ready, try again in 1 minutes" << std::endl;
      m_scheduler->schedule(time::seconds(60), [this] {
          syncFileName();
      });
      return;
    }
        std::string configPath = DEFAULT_CONFIG_FILE;
        bool showImplicitDigest = false;
        RepoEnumerator instance(configPath);
        std::list<ndn::Name> file_names = instance.getFileNames();
        for (auto name = file_names.begin();name!=file_names.end();name++){
          sendNewFileInterest(*name);
        }
    }
  void sendNewFileInterest(ndn::Name contentName)
  {
    Name name("/ndn/nd/file");
    name.append((uint8_t*)&m_IP, sizeof(m_IP)).append((uint8_t*)&m_port, sizeof(m_port));
    name.appendNumber(contentName.size()).append(contentName).appendTimestamp();

    Interest interest(name);
    interest.setInterestLifetime(30_s);
    interest.setMustBeFresh(true);
    interest.setNonce(4);
    interest.setCanBePrefix(false); 

    cout << "NDND (Client): Sending new file Interest: " << interest << endl;

    m_face.expressInterest(interest, nullptr, bind(&NDNDClient::onNack, this, _1, _2), //no expectation
                           nullptr); //no expectation
  }


  void registerSubPrefix()
  {
    Name name(m_prefix);
    name.append("nd-info");
    m_face.setInterestFilter(InterestFilter(name), bind(&NDNDClient::onSubInterest, this, _2), nullptr);
    cout << "NDND (Client): Register Prefix: " << name << endl;
  }
//Listen for advertise request
  void registerAdvertisePrefix()
  {
    Name name(m_advertise_prefix);
    m_face.setInterestFilter(InterestFilter(name), bind(&NDNDClient::onAdvertiseInterest, this, _2), nullptr);
    //TODO get prefix out and register
    cout << "NDND (Client-Adertise): Register Prefix: " << name << endl;
  }

  void sendSubInterest()
  {
    // Wait for face to ND Server to be registered in NFD
    if (!is_ready)
      return;
    Name name("/ndn/nd");
    name.appendTimestamp();
    Interest interest(name);
    interest.setInterestLifetime(30_s);
    interest.setMustBeFresh(true);
    interest.setNonce(4);
    interest.setCanBePrefix(false);
cout << "NDND (Client): Sending /ndn/nd Request: " << interest << endl;
    m_face.expressInterest(interest,
                           bind(&NDNDClient::onSubData, this, _1, _2),
                           bind(&NDNDClient::onNack, this, _1, _2),
                           bind(&NDNDClient::onTimeout, this, _1));
  }

 
// private:
  void onSubData(const Interest& interest, const Data& data)
  {
    std::cout << data << std::endl;

    size_t dataSize = data.getContent().value_size();
    auto pResult = reinterpret_cast<const RESULT*>(data.getContent().value());
    int iNo = 1;
    Name name;

    while((uint8_t*)pResult < data.getContent().value() + dataSize){
      m_len = sizeof(RESULT);
      printf("-----%2d-----\n", iNo);
      printf("IP: %s\n", inet_ntoa(*(in_addr*)(pResult->IpAddr)));
      std::stringstream ss;
      ss << "udp4://" << inet_ntoa(*(in_addr*)(pResult->IpAddr)) << ':' << ntohs(pResult->Port);
      printf("Port: %hu\n", ntohs(pResult->Port));

      auto result = Block::fromBuffer(pResult->NamePrefix, data.getContent().value() + dataSize - pResult->NamePrefix);
      name.wireDecode(std::get<1>(result));
      printf("Name Prefix: %s\n", name.toUri().c_str());
      m_len += std::get<1>(result).size();

      pResult = reinterpret_cast<const RESULT*>(((uint8_t*)pResult) + m_len);
      iNo ++;

      m_uri_to_prefix[ss.str()] = name.toUri();
      cout << "URI: " << ss.str() << endl;

      // Do not register route to myself
      std::string myIp = inet_ntoa(m_IP);
      std::string resultIp = inet_ntoa(*(in_addr*)(pResult->IpAddr));
      if (myIp == resultIp) {
        cout << "My IP address returned"<<inet_ntoa(*(in_addr*)(pResult->IpAddr))<<inet_ntoa(m_IP)<< endl;
        continue;
      }
      addFace(ss.str());
      setStrategy(name.toUri(), BEST_ROUTE);
    }
  }

  void onNack(const Interest& interest, const lp::Nack& nack)
  {
    std::cout << "received Nack with reason " << nack.getReason()
              << " for interest " << interest << std::endl;
  }

  void onTimeout(const Interest& interest)
  {
    std::cout << "Timeout " << interest << std::endl;
  }

  void onRegisterRouteDataReply(const Interest& interest, const Data& data,
                                bool is_server_route)
  {
    Block response_block = data.getContent().blockFromValue();
    response_block.parse();

    std::cout << "Register Data Reply"<<response_block << std::endl;

    Block status_code_block = response_block.get(STATUS_CODE);
    Block status_text_block = response_block.get(STATUS_TEXT);
    short response_code = readNonNegativeIntegerAs<int>(status_code_block);
    char response_text[1000] = {0};
    memcpy(response_text, status_text_block.value(), status_text_block.value_size());

    if (response_code == OK) {

      Block control_params = response_block.get(CONTROL_PARAMETERS);
      control_params.parse();

      Block name_block = control_params.get(ndn::tlv::Name);
      Name route_name(name_block);
      Block face_id_block = control_params.get(FACE_ID);
      int face_id = readNonNegativeIntegerAs<int>(face_id_block);
      Block origin_block = control_params.get(ORIGIN);
      int origin = readNonNegativeIntegerAs<int>(origin_block);
      Block route_cost_block = control_params.get(COST);
      int route_cost = readNonNegativeIntegerAs<int>(route_cost_block);
      Block flags_block = control_params.get(FLAGS);
      int flags = readNonNegativeIntegerAs<int>(flags_block);

      std::cout << "\nRegistration of route succeeded:" << std::endl;
      std::cout << "Status text: " << response_text << std::endl;
      std::cout << "Route name: " << route_name.toUri() << std::endl;
      std::cout << "Face id: " << face_id << std::endl;
      std::cout << "Origin: " << origin << std::endl;
      std::cout << "Route cost: " << route_cost << std::endl;
      std::cout << "Flags: " << flags << std::endl;

      if (is_server_route) {
        is_ready = true;
        std::cout << "NDND (Client): Bootstrap succeeded\n";
      }

      is_ready = true;
    }
    else {
      std::cout << "\nRegistration of route failed." << std::endl;
      std::cout << "Status text: " << response_text << std::endl;
    }
  }

  void onAddFaceDataReply(const Interest& interest, const Data& data,
                          const string& uri, bool is_server_face) 
  {
    short response_code;
    char response_text[1000] = {0};
    char buf[1000]           = {0};   // For parsing
    int face_id;                      // Store faceid for deletion of face
    Block response_block = data.getContent().blockFromValue();
    response_block.parse();

    Block status_code_block = response_block.get(STATUS_CODE);
    Block status_text_block = response_block.get(STATUS_TEXT);
    response_code = readNonNegativeIntegerAs<int>(status_code_block);
    memcpy(response_text, status_text_block.value(), status_text_block.value_size());

    // Get FaceId for future removal of the face
    if (response_code == OK || response_code == FACE_EXISTS) {
      Block status_parameter_block =  response_block.get(CONTROL_PARAMETERS);
      status_parameter_block.parse();
      Block face_id_block = status_parameter_block.get(FACE_ID);
      face_id = readNonNegativeIntegerAs<int>(face_id_block);
      std::cout << response_code << " " << response_text << ": Added Face (FaceId: "
                << face_id << "): " << uri << std::endl;

      auto it = m_uri_to_prefix.find(uri);
      if (is_server_face) {
        //TODO: Add cost
        //RegisterRounte(Name, face_id,cost, is_server_face)
        registerRoute(Name("/ndn/nd"), face_id,10, is_server_face);
        m_server_faceid = face_id;
      }
      else if (it != m_uri_to_prefix.end()) {
        registerRoute(it->second, face_id, 0, is_server_face);
        //registerRoute(it->second, m_server_faceid, 10, is_server_face);
      }
      else {
	      std::cerr << "Failed to find prefix for uri " << uri << std::endl;
      }

    }
    else {
      std::cout << "\nCreation of face failed." << std::endl;
      std::cout << "Status text: " << response_text << std::endl;
    }
  }

  void onDestroyFaceDataReply(const Interest& interest, const Data& data) 
  {
    short response_code;
    char response_text[1000] = {0};
    char buf[1000]           = {0};   // For parsing
    int face_id;
    Block response_block = data.getContent().blockFromValue();
    response_block.parse();

    Block status_code_block =       response_block.get(STATUS_CODE);
    Block status_text_block =       response_block.get(STATUS_TEXT);
    Block status_parameter_block =  response_block.get(CONTROL_PARAMETERS);
    memcpy(buf, status_code_block.value(), status_code_block.value_size());
    response_code = *(short *)buf;
    memcpy(response_text, status_text_block.value(), status_text_block.value_size());

    status_parameter_block.parse();
    Block face_id_block = status_parameter_block.get(FACE_ID);
    memset(buf, 0, sizeof(buf));
    memcpy(buf, face_id_block.value(), face_id_block.value_size());
    face_id = ntohs(*(int *)buf);

    std::cout << response_code << " " << response_text << ": Destroyed Face (FaceId: "
              << face_id << ")" << std::endl;
  }

  void addFace(const string& uri, bool is_server_face = false) 
  {
    printf("NDND (Client): Adding face: %s\n", uri.c_str());
    Interest interest = prepareFaceCreationInterest(uri, m_keyChain,0);
    m_face.expressInterest(
      interest,
      bind(&NDNDClient::onAddFaceDataReply, this, _1, _2, uri, is_server_face),
      bind(&NDNDClient::onNack, this, _1, _2),
      bind(&NDNDClient::onTimeout, this, _1));
  }

  void destroyFace(int face_id) 
  {
    Interest interest = prepareFaceDestroyInterest(face_id, m_keyChain);
    m_face.expressInterest(
      interest,
      bind(&NDNDClient::onDestroyFaceDataReply, this, _1, _2),
      bind(&NDNDClient::onNack, this, _1, _2),
      bind(&NDNDClient::onTimeout, this, _1));
  }

  void onSetStrategyDataReply(const Interest& interest, const Data& data) 
  {
    Block response_block = data.getContent().blockFromValue();
    response_block.parse();
    int responseCode = readNonNegativeIntegerAs<int>(response_block.get(STATUS_CODE));
    std::string responseTxt = readString(response_block.get(STATUS_TEXT));

    if (responseCode == OK) {
      Block status_parameter_block = response_block.get(CONTROL_PARAMETERS);
      status_parameter_block.parse();
      std::cout << "\nSet strategy succeeded." << std::endl;
    } else {
      std::cout << "\nSet strategy failed." << std::endl;
      std::cout << "Status text: " << responseTxt << std::endl;
    }
  }

  void setStrategy(const string& uri, const string& strategy) 
  {
    Interest interest = prepareStrategySetInterest(uri, strategy, m_keyChain);
    m_face.expressInterest(
      interest,
      bind(&NDNDClient::onSetStrategyDataReply, this, _1, _2),
      bind(&NDNDClient::onNack, this, _1, _2),
      bind(&NDNDClient::onTimeout, this, _1));
  }

  void setIP() 
  {
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];
    char netmask[NI_MAXHOST];
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
      if (ifa->ifa_addr == NULL)
        continue;

      s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
      s=getnameinfo(ifa->ifa_netmask,sizeof(struct sockaddr_in),netmask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

      if (ifa->ifa_addr->sa_family==AF_INET) {
        if (s != 0) {
          printf("getnameinfo() failed: %s\n", gai_strerror(s));
          exit(EXIT_FAILURE);
        }
        if (ifa->ifa_name[0] == 'l' && ifa->ifa_name[1] == 'o')   // Loopback
          continue;
        printf("\tInterface : <%s>\n", ifa->ifa_name);
        printf("\t  Address : <%s>\n", host);
        inet_aton(host, &m_IP);
        inet_aton(netmask, &m_submask);
        break;
      }
    }
    freeifaddrs(ifaddr);
  }

public:
  bool is_ready = false;    // Ready after creating face and route to ND server
  Face m_face;
  KeyChain m_keyChain;
  Name m_prefix;
  Name m_advertise_prefix;
  Name m_server_prefix;
  in_addr m_IP;
  in_addr m_submask;
  Scheduler *m_scheduler;
  in_addr m_server_IP;
  int m_server_faceid;
  uint16_t m_port;
  uint8_t m_buffer[4096];
  size_t m_len;
  std::map<std::string, std::string> m_uri_to_prefix;
  //Sync up names to advertise
  std::list<ndn::Name> m_chatinfo;
};


class Program
{
public:
  explicit Program(const Options& options)
    : m_options(options)
  {
    // Init client
    m_client = new NDNDClient(m_options.m_prefix,
                              m_options.m_advertise_prefix,
                              m_options.server_prefix, 
                              m_options.server_ip);

    m_scheduler = new Scheduler(m_client->m_face.getIoService());
    m_client->registerSubPrefix();
    m_client->registerAdvertisePrefix();
    m_scheduler->schedule(time::seconds(5), [this] {
    loop();
    });
    //loop();
  }

  void loop() {
    std::cout<<"Next sync start"<<std::endl;
    m_client->sendSubInterest();
    m_client->syncFileName();
    m_client->syncChatInfo();
    m_client->sendArrivalInterest();

    m_scheduler->schedule(time::seconds(180), [this] {
      loop();
    });
  }

  ~Program() {
    delete m_client;
    delete m_scheduler;
  }

  NDNDClient *m_client;

private:
  const Options m_options;
  Scheduler *m_scheduler;
  boost::asio::io_service m_io_service;
};


int
main(int argc, char** argv)
{
  //getLocalFileNames();
  /*
  std::string configPath = DEFAULT_CONFIG_FILE;
  bool showImplicitDigest = false;
  RepoEnumerator instance(configPath);
  std::list<ndn::Name> file_names = instance.getFileNames();
  std::list<ndn::Name>::iterator name;
  for (name = file_names.begin();name!=file_names.end();name++){
    std::cout<<name<<std::endl;
  }
  */
  ////////////////////////////////////////////////////
  Options opt;
  //////////////////////////////////////
   po::options_description options("Required options");
  options.add_options()
    ("help,h", "print help message")
    ("server_ip,ip", po::value<std::string>(&opt.server_ip), "server IP");
  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argc, argv, options), vm);
    po::notify(vm);
  }
  catch (boost::program_options::error&) {
    usage(std::cerr, options);
    return 2;
  }
  ///////////////////////////////////////////////// 
  Program program(opt);
  program.m_client->m_face.processEvents();

}