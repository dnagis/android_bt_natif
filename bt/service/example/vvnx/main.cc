/**
 * Mix entre system/bt/service/example/heart-rate et system/bt/service/client
 * pour builder placer dans system/bt/service/example/vvnx/ et modifier
 * le service/Android.bp (créer une target similaire à celle de bt-example-hr-server)
 * 
 * adb push out/target/product/mido/system/bin/bt-vvnx /system/bin
 * le context SELinux, c'est surtout pour faire lancer par init, à la mano pas la peine
 * chcon u:object_r:bluetoothtbd_exec:s0 /system/bin/bt-vvnx
 * 
 * 
 * Pour la comm bluetooth
 *  en face j'ai bluez avec leadv avec dedans:
 *  vvnx_hci_le_set_scan_resp(int dd)
	taille = 3;
	uint8_t scan_resp_vvnx[3] = {0x02, 0xff, 0x0a};
 * 
 * et dans
 * 
 * vvnx_hci_le_set_adv_data
	taille = 10;
	uint8_t adv_data_vvnx[31] = {0x02, 0x01, 0x06, 0x03, 0x03, 0x09, 0x18, 0x02, 0x0a, 0x0c};
 *  
 * et je reçois:
 * Scan result: 14:4F:8A:06:C7:EA - Record: 02010603030918020A0C02FF0A - RSSI: -6
 * 
 * 
 * selinux: lui donner le même contexte que bluetoothtbd
 * à chaque compil/push:
 * chcon u:object_r:bluetoothtbd_exec:s0 /system/bin/bt-vvnx
 * allow bluetoothtbd self:binder { call transfer };
 * 
 * pour la db, sqlite3:
 * dans Android.bp include_dirs: ["external/sqlite/dist"], et shared_libs: [ ...."libsqlite", ]
 * chcon u:object_r:bluetooth_data_file:s0 /system/usr/share/vvnx/bt_log_vvnx.db
 * 
 * 
 * 
 * 
 */
#include <iostream>
#include <string>
#include <thread>
#include <sys/time.h>

//external/libchrome/base/
#include <base/at_exit.h>
#include <base/bind.h>
#include <base/command_line.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/message_loop/message_loop.h>
#include <base/run_loop.h>
#include <base/strings/string_number_conversions.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <bluetooth/low_energy_constants.h>

//des includes aidl dans system/bt/service/common/android/bluetooth, globalement tout à l'air d'être là
//une Bn interface c'est quoi?? -> http://pierrchen.blogspot.com/2015/06/yet-another-deep-dive-of-android-binder.html

#include <android/bluetooth/BnBluetoothLowEnergyCallback.h>
#include <android/bluetooth/IBluetooth.h>
#include <android/bluetooth/IBluetoothLowEnergy.h>
#include <android/bluetooth/IBluetoothLeScanner.h>
#include <android/bluetooth/BnBluetoothLeScannerCallback.h>

#include <sqlite3.h>

using namespace std;

using android::sp;
using android::OK;
using android::bluetooth::IBluetooth;
using android::bluetooth::IBluetoothLowEnergy;
using android::bluetooth::IBluetoothLeScanner;

using android::getService;
using android::String16;
using android::binder::Status;

namespace {

std::string kServiceName = "bluetooth-service";

// The registered IBluetoothLowEnergy client handle. If |ble_registering| is
// true then an operation to register the client is in progress.
std::atomic_bool ble_registering(false);
std::atomic_int ble_client_id(0);

// The registered IBluetoothLeScanner handle. If |ble_scanner_registering| is
// true then an operation to register the scanner is in progress.
std::atomic_bool ble_scanner_registering(false);
std::atomic_int ble_scanner_id(0);

//void PrintVvnx(const string& message) {  cout << message << endl; }



class CLIBluetoothLowEnergyCallback
    : public android::bluetooth::BnBluetoothLowEnergyCallback {
 public:
  CLIBluetoothLowEnergyCallback() = default;
  ~CLIBluetoothLowEnergyCallback() override = default;

  // IBluetoothLowEnergyCallback overrides:
  Status OnClientRegistered(int status, int client_id) override {
    if (status != bluetooth::BLE_STATUS_SUCCESS) {
      LOG(ERROR) << "Failed to register BLE client";
    } else {
      ble_client_id = client_id;
      LOG(INFO) << "Registered BLE client with ID: " << client_id;
    }
    ble_registering = false;
    return Status::ok();
  }

  Status OnConnectionState(int status, int client_id, const String16& address,
                           bool connected) override {
    LOG(INFO) << "Connection state: " << address << " connected: " << (connected ? "true" : "false") << "- status: " << status << " - client_id: " << client_id;
    return Status::ok();
  }

  Status OnMtuChanged(int status, const String16& address, int mtu) override {
    LOG(INFO) << "MTU changed: " << address << " - status: " << status << " - mtu: " << mtu;
    return Status::ok();
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(CLIBluetoothLowEnergyCallback);
}; 

class CLIBluetoothLeScannerCallback
    : public android::bluetooth::BnBluetoothLeScannerCallback {
 public:
  CLIBluetoothLeScannerCallback() = default;
  ~CLIBluetoothLeScannerCallback() override = default;

  // IBluetoothLowEnergyCallback overrides:
  Status OnScannerRegistered(int status, int scanner_id) override {
    if (status != bluetooth::BLE_STATUS_SUCCESS) {
       LOG(ERROR) << "Failed to register BLE client";
    } else {
      ble_scanner_id = scanner_id;
      LOG(INFO) << "Registered Scanner with ID: " << scanner_id;
    }
    ble_scanner_registering = false;   
    
    return Status::ok();
  }

  Status OnScanResult(
      const android::bluetooth::ScanResult& scan_result) override {
 
	//LOG(INFO) << "Scan result: " << scan_result.device_address() << " - Record: " << base::HexEncode(scan_result.scan_record().data(),
	//                          scan_result.scan_record().size()) << " - RSSI: " << scan_result.rssi() << " - Size: " << scan_result.scan_record().size();
	//base::HexEncode et base::IntToString -> def dans external/libchrome/base/strings/string_number_conversions.[h,cc]
    
    if (scan_result.device_address().compare("30:AE:A4:04:C8:2E") == 0) {
		struct timeval curr_tv;
		gettimeofday(&curr_tv, NULL);  
		long time_now;
		time_now = curr_tv.tv_sec;
				  
	    const char * data_adv_vvnx = reinterpret_cast<const char*>(scan_result.scan_record().data());
	    LOG(INFO) << "temp: temp_pos?: " << base::IntToString(data_adv_vvnx[4]) << "  temp: " << base::IntToString(data_adv_vvnx[5]) << "." << base::IntToString(data_adv_vvnx[6]) << " time_now: " << time_now;
		
		/* Vu comme j'en ai chié je laisse ça parce que c'est surement pas la dernière fois que tu galères avec des pointeurs et des vectors
		const uint8_t * mon_pointeur = scan_result.scan_record().data(); *****pointeur****** vers la data, donc on est bien d'accord: c'est une adresse pas une valeur	
		uint8_t valeur = *mon_pointeur; valeur est la valeur qu'il y a à l'adresse définie par "premier"
		LOG(INFO) << "1-> " << base::IntToString(valeur);   LOG(INFO) n'affiche pas les uint8_t, c'est vide. faut transfo en string
		mon_pointeur ++; on va a l'adresse suivante (tu peux aussi faire += 1
		valeur = *mon_pointeur;
		LOG(INFO) << "2-> " << base::IntToString(valeur);*/
		
		std::string temp = base::IntToString(data_adv_vvnx[5]) + "." + base::IntToString(data_adv_vvnx[6]);
				
		sqlite3 *db;
		int rc;		  
		//pourquoi /data/misc/bluedroid/ ??? --> parce que sepolicy/private/file_contexts et bluetoothtbd.te
		rc = sqlite3_open("/data/misc/bluedroid/bt_log_vvnx.db", &db);
		//CREATE TABLE tbl1(date integer, temp text);
		if( rc )
			LOG(ERROR) << "Can't open database: " << sqlite3_errmsg(db) ;
					
		char *zErrMsg = 0;	
				
		std::string stmt = "insert into tbl1 values(" + to_string(time_now) + ", '" + temp + " ');";
		
		rc = sqlite3_exec(db, stmt.c_str(), NULL, 0, &zErrMsg);
		
		if( rc!=SQLITE_OK )
			{
			LOG(ERROR) << "SQL error: " << sqlite3_errmsg(db);
			sqlite3_free(zErrMsg);
			}
				
		
		}
    
    return Status::ok();
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(CLIBluetoothLeScannerCallback);
};

void HandleRegisterBLE(IBluetooth* bt_iface) {

  if (ble_registering.load()) {
    LOG(INFO) << "In progress";
    return;
  }

  if (ble_client_id.load()) {
    LOG(INFO) << "Already registered";
    return;
  }

  sp<IBluetoothLowEnergy> ble_iface;
  bt_iface->GetLowEnergyInterface(&ble_iface);
  if (!ble_iface.get()) {
    LOG(ERROR) << "Failed to obtain handle to Bluetooth Low Energy interface";
    return;
  }
  
  //si il a pas return plus haut c'est que tout s'est bien passé non???
  LOG(INFO) << "...dans HandleRegisterBLE...";


  bool status;
  ble_iface->RegisterClient(new CLIBluetoothLowEnergyCallback(), &status);
  ble_registering = status;
  LOG(INFO) <<  "status RegisterClient: " << status;
}



void HandleRegisterBLEScanner(IBluetooth* bt_iface) {
  
  if (ble_scanner_registering.load()) {
    LOG(INFO) << "In progress";
    return;
  }

  if (ble_scanner_id.load()) {
    LOG(ERROR) << "Already registered";
    return;
  }

  sp<IBluetoothLeScanner> ble_scanner_iface;
  bt_iface->GetLeScannerInterface(&ble_scanner_iface);
  if (!ble_scanner_iface.get()) {
    LOG(ERROR) << "Failed to obtain handle to Bluetooth LE Scanner interface";
    return;
  }

  bool status;
  ble_scanner_iface->RegisterScanner(new CLIBluetoothLeScannerCallback(), &status);
  ble_scanner_registering = status;
  
  //tant qu'on a pas register le scanner on peut pas lancer un start scan car on a pas le bon int ble_scanner_id
    do {  sleep(1); } while  (ble_scanner_registering == true); 
    
  //on scanne  
	bluetooth::ScanSettings settings;
	std::vector<android::bluetooth::ScanFilter> filters;  
	ble_scanner_iface->StartScan(ble_scanner_id.load(), settings, filters, &status);  
	LOG(INFO) <<  "StartScan lancé status :" << status;
	sleep (40); //les résultats de scan arrivent dans la callback.
	ble_scanner_iface->StopScan(ble_scanner_id.load(), &status); //stop scan
	LOG(INFO) <<  "StopScan status :" << status;
	android::IPCThreadState::self()->stopProcess();
  
}


void QuitMessageLoop() {
  // I don't know why both of these calls are necessary but the message loop
  // doesn't stop unless I call both. Bug in base::MessageLoop?
  base::RunLoop().Quit();
  base::MessageLoop::current()->QuitNow();
}

/*void AutoKillVvnx() {  
	LOG(INFO) << "Début AutoKill, sleep 60 secondes";
	sleep(60);
	LOG(INFO) << "AutoKill fin sleep on tue message loop";
	android::IPCThreadState::self()->stopProcess();
	QuitMessageLoop();	
	}*/

// Handles the case where the Bluetooth process dies.
class BluetoothDeathRecipient : public android::IBinder::DeathRecipient {
 public:
  explicit BluetoothDeathRecipient(
      scoped_refptr<base::SingleThreadTaskRunner> main_task_runner)
      : main_task_runner_(main_task_runner) {}

  ~BluetoothDeathRecipient() override = default;

  // android::IBinder::DeathRecipient override:
  void binderDied(const android::wp<android::IBinder>& /* who */) override {
    LOG(ERROR) << "The Bluetooth daemon has died. Aborting.";

    // binderDied executes on a dedicated thread. We need to stop the main loop
    // on the main thread so we post a message to it here. The main loop only
    // runs on the main thread.
    main_task_runner_->PostTask(FROM_HERE, base::Bind(&QuitMessageLoop));

    android::IPCThreadState::self()->stopProcess();
  }

 private:
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;
};

}  // namespace

int main(int argc, char* argv[]) {
  base::AtExitManager exit_manager;
  base::CommandLine::Init(argc, argv);
  logging::LoggingSettings log_settings;
  
  // Initialize global logging based on command-line parameters (this is a
  // libchrome pattern).
  if (!logging::InitLogging(log_settings)) {
    LOG(ERROR) << "Failed to set up logging";
    return EXIT_FAILURE;
  }

  // Set up a message loop so that we can schedule timed Heart Rate
  // notifications.
  base::MessageLoop main_loop;
  
  int dodo_initial = 20; //30 sec si démarrage par .rc; super moche je sais mais bon... le startup d'Android c'est pas simple!
  
  LOG(INFO) << "Starting VVNX début de main on sleep " << dodo_initial << "s";
  
  sleep(dodo_initial); 

  

  sp<IBluetooth> bt_iface;
  status_t status = getService(String16(kServiceName.c_str()), &bt_iface);
  if (status != OK) {
    LOG(ERROR) << "Failed to get service binder: '" << kServiceName
               << "' status=" << status;
    return EXIT_FAILURE;
  }

  // Bluetooth needs to be enabled for our demo to work.
  bool enabled;
  bt_iface->IsEnabled(&enabled);
  if (!enabled) {
    LOG(ERROR) << "Bluetooth is not enabled.";
    return EXIT_FAILURE;
  }

  // Register for death notifications on the IBluetooth binder. This let's us
  // handle the case where the Bluetooth daemon process (bluetoothtbd) dies
  // outside of our control.
  sp<BluetoothDeathRecipient> dr(
      new BluetoothDeathRecipient(main_loop.task_runner()));
  if (android::IInterface::asBinder(bt_iface.get())->linkToDeath(dr) !=
      android::NO_ERROR) {
    LOG(ERROR) << "Failed to register DeathRecipient for IBluetooth";
    return EXIT_FAILURE;
  }

  // Initialize the Binder process thread pool. We have to set this up,
  // otherwise, incoming callbacks from the Bluetooth daemon would block the
  // main thread (in other words, we have to do this as we are a "Binder
  // server").
  android::ProcessState::self()->startThreadPool();
  
  
  //std::thread t1(AutoKillVvnx);
  
  
  //Mes actions (trouvée en CLI avec le client à la mano)
  LOG(INFO) << "On va lancer les HandleRegisterBLE";
  HandleRegisterBLE(bt_iface.get());
  HandleRegisterBLEScanner(bt_iface.get());
  
  
  //LOG(INFO) << "On va lancer le message loop";
  //main_loop.Run();

  LOG(INFO) << "Exiting";
  return EXIT_SUCCESS;
}
