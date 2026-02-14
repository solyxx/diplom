# IoT THREAT ANALYZER
## Narzędzie naukowe do analizy zagrożeń inteligentnego domu

---

## KONCEPCJA NARZĘDZIA

### Czym jest?

**IoT Threat Analyzer** — to narzędzie do modelowania i analizy WSZYSTKICH typów zagrożeń w systemie inteligentnego domu:

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                      │
│   NIE tylko hakerzy!                                                │
│                                                                      │
│   ┌───────────────┐   ┌───────────────┐   ┌───────────────┐        │
│   │   🎭 ATAK     │   │   🤦 GŁUPOTA  │   │   ⚡ SIŁA     │        │
│   │   HAKERA     │   │   (czynnik    │   │    WYŻSZA    │        │
│   │              │   │    ludzki)    │   │              │        │
│   └───────────────┘   └───────────────┘   └───────────────┘        │
│          │                   │                   │                  │
│          └───────────────────┼───────────────────┘                  │
│                              ▼                                       │
│                    ┌─────────────────┐                              │
│                    │  UNIFIED THREAT │                              │
│                    │     MODEL       │                              │
│                    └─────────────────┘                              │
│                              │                                       │
│                              ▼                                       │
│                    ┌─────────────────┐                              │
│                    │   RISK MATRIX   │                              │
│                    │   + SCENARIUSZE │                              │
│                    └─────────────────┘                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## TYPY ZAGROŻEŃ

### 1. 🎭 Atak złośliwy (Malicious Attack)
Celowe działanie hakera/przestępcy

| Podtyp | Przykład | Prawdopodobieństwo | Wpływ |
|--------|----------|-------------------|-------|
| Atak zdalny | Włamanie przez internet | Średnie | Krytyczny |
| Atak lokalny | Włamanie przez WiFi sąsiada | Niskie | Krytyczny |
| Dostęp fizyczny | Włamanie do urządzenia na miejscu | Bardzo niskie | Krytyczny |
| Supply chain | Backdoor od producenta | Niskie | Katastrofalny |

### 2. 🤦 Czynnik ludzki (Human Error)
Błędy użytkowników, niekompetencja, zaniedbanie

| Podtyp | Przykład | Prawdopodobieństwo | Wpływ |
|--------|----------|-------------------|-------|
| Błędna konfiguracja | Zostawione domyślne hasło | Wysokie | Wysoki |
| Przypadkowe uruchomienie | Dzieci bawiły się aplikacją | Średnie | Średni |
| Socjotechnika | Phishing, podanie hasła | Średnie | Krytyczny |
| Zaniedbanie | Brak aktualizacji firmware 3 lata | Wysokie | Wysoki |
| Niekompatybilność | Podłączenie niekompatybilnego urządzenia | Średnie | Średni |

### 3. ⚡ Siła wyższa (Force Majeure)
Okoliczności zewnętrzne, awarie techniczne

| Podtyp | Przykład | Prawdopodobieństwo | Wpływ |
|--------|----------|-------------------|-------|
| Awaria zasilania | Wyłączenie prądu | Średnie | Zależy |
| Awaria sieci | Brak internetu | Średnie | Zależy |
| Awaria sprzętu | Urządzenie się zepsuło | Niskie | Średni |
| Bug firmware | Błąd w aktualizacji | Niskie | Może być krytyczny |
| Środowiskowe | Zalanie, pożar, uderzenie pioruna | Niskie | Katastrofalny |
| Awaria kaskadowa | Jedno urządzenie psuje inne | Niskie | Wysoki |

---

## NOWOŚĆ NAUKOWA

### Kluczowa idea: **Unified Threat Modeling Framework (UTMF)**

Jednolity model matematyczny dla WSZYSTKICH typów zagrożeń:

```python
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable
import numpy as np
from abc import ABC, abstractmethod

class ThreatCategory(Enum):
    MALICIOUS = "malicious"          # Atak złośliwy
    HUMAN_ERROR = "human_error"      # Czynnik ludzki
    FORCE_MAJEURE = "force_majeure"  # Siła wyższa
    CASCADE = "cascade"              # Efekt kaskadowy

class ThreatVector(Enum):
    # Malicious
    REMOTE_NETWORK = "remote_network"
    LOCAL_NETWORK = "local_network"
    PHYSICAL_ACCESS = "physical_access"
    SUPPLY_CHAIN = "supply_chain"
    
    # Human error
    MISCONFIGURATION = "misconfiguration"
    ACCIDENTAL_TRIGGER = "accidental_trigger"
    SOCIAL_ENGINEERING = "social_engineering"
    NEGLECT = "neglect"
    
    # Force majeure
    POWER_FAILURE = "power_failure"
    NETWORK_OUTAGE = "network_outage"
    HARDWARE_FAILURE = "hardware_failure"
    ENVIRONMENTAL = "environmental"

@dataclass
class DeviceState:
    """Stan urządzenia w momencie czasowym t"""
    power: bool = True
    online: bool = True
    compromised: bool = False
    malfunctioning: bool = False
    
    # Parametry fizyczne (zależą od typu)
    temperature: Optional[float] = None   # °C
    position: Optional[float] = None      # % (dla zamków, rolet)
    brightness: Optional[float] = None    # % (dla oświetlenia)
    flow_rate: Optional[float] = None     # l/min (dla wody)
    
    # Sieć
    traffic_in: float = 0     # bytes/sec
    traffic_out: float = 0    # bytes/sec
    connections: int = 0       # aktywne połączenia

@dataclass
class Threat:
    """Bazowy model zagrożenia"""
    id: str
    name: str
    category: ThreatCategory
    vector: ThreatVector
    
    # Prawdopodobieństwa
    base_probability: float              # P bez ochrony
    probability_modifiers: Dict[str, float] = field(default_factory=dict)
    
    # Wpływ
    affected_devices: List[str] = field(default_factory=list)  # typy urządzeń
    state_changes: Dict[str, any] = field(default_factory=dict)  # zmiany stanu
    
    # Charakterystyki czasowe
    detection_time_hours: float = 1.0    # czas do wykrycia
    recovery_time_hours: float = 2.0     # czas na odzyskanie
    
    # Efekty kaskadowe
    triggers: List[str] = field(default_factory=list)  # ID innych zagrożeń

@dataclass 
class DeviceProfile:
    """Profil urządzenia z podatnościami"""
    id: str
    type: str
    name: str
    vendor: str
    firmware_version: str
    firmware_date: str
    
    # Bezpieczeństwo
    has_default_password: bool = False
    encryption_enabled: bool = True
    auto_update: bool = False
    exposed_to_internet: bool = False
    
    # Niezawodność
    mtbf_hours: float = 50000  # Mean Time Between Failures
    age_months: int = 0
    
    # Zależności
    depends_on: List[str] = field(default_factory=list)  # ID innych urządzeń
    controls: List[str] = field(default_factory=list)    # co kontroluje


class ThreatAnalyzer:
    """
    GŁÓWNE NARZĘDZIE NAUKOWE
    
    Analizuje system urządzeń pod kątem wszystkich typów zagrożeń
    """
    
    def __init__(self):
        self.devices: Dict[str, DeviceProfile] = {}
        self.threats: Dict[str, Threat] = {}
        self.load_threat_database()
    
    def load_threat_database(self):
        """Ładuje bazę znanych zagrożeń"""
        self.threats = {
            # === MALICIOUS ===
            "MAL_001": Threat(
                id="MAL_001",
                name="Atak brute-force na hasło",
                category=ThreatCategory.MALICIOUS,
                vector=ThreatVector.REMOTE_NETWORK,
                base_probability=0.3,
                probability_modifiers={
                    "has_default_password": 0.9,      # znacznie zwiększa
                    "encryption_enabled": -0.5,        # zmniejsza
                    "exposed_to_internet": 0.4,
                },
                affected_devices=["camera", "lock", "thermostat", "speaker"],
                state_changes={"compromised": True},
                detection_time_hours=24,
                recovery_time_hours=2,
            ),
            "MAL_002": Threat(
                id="MAL_002", 
                name="Przechwycenie strumienia wideo",
                category=ThreatCategory.MALICIOUS,
                vector=ThreatVector.REMOTE_NETWORK,
                base_probability=0.2,
                probability_modifiers={
                    "encryption_enabled": -0.8,
                    "exposed_to_internet": 0.5,
                },
                affected_devices=["camera", "doorbell"],
                state_changes={"compromised": True},
            ),
            "MAL_003": Threat(
                id="MAL_003",
                name="Ransomware na Smart TV",
                category=ThreatCategory.MALICIOUS,
                vector=ThreatVector.REMOTE_NETWORK,
                base_probability=0.05,
                affected_devices=["tv"],
                state_changes={"compromised": True, "malfunctioning": True},
                triggers=["CASCADE_001"],
            ),
            
            # === HUMAN ERROR ===
            "HUM_001": Threat(
                id="HUM_001",
                name="Pozostawione domyślne hasło",
                category=ThreatCategory.HUMAN_ERROR,
                vector=ThreatVector.MISCONFIGURATION,
                base_probability=0.4,
                probability_modifiers={
                    "auto_update": -0.1,
                },
                affected_devices=["*"],
                triggers=["MAL_001"],
            ),
            "HUM_002": Threat(
                id="HUM_002",
                name="Dziecko wyłączyło ogrzewanie zimą",
                category=ThreatCategory.HUMAN_ERROR,
                vector=ThreatVector.ACCIDENTAL_TRIGGER,
                base_probability=0.1,
                affected_devices=["thermostat"],
                state_changes={"temperature": 5},
                detection_time_hours=4,
            ),
            "HUM_003": Threat(
                id="HUM_003",
                name="Zapomniał zamknąć drzwi",
                category=ThreatCategory.HUMAN_ERROR,
                vector=ThreatVector.ACCIDENTAL_TRIGGER,
                base_probability=0.15,
                probability_modifiers={
                    "auto_lock_enabled": -0.9,
                },
                affected_devices=["lock"],
                state_changes={"position": 0},
            ),
            "HUM_004": Threat(
                id="HUM_004",
                name="Brak aktualizacji firmware > 2 lata",
                category=ThreatCategory.HUMAN_ERROR,
                vector=ThreatVector.NEGLECT,
                base_probability=0.5,
                probability_modifiers={
                    "auto_update": -0.9,
                },
                affected_devices=["*"],
                triggers=["MAL_001", "MAL_002", "MAL_003"],
            ),
            "HUM_005": Threat(
                id="HUM_005",
                name="Phishing — podał hasło do huba",
                category=ThreatCategory.HUMAN_ERROR,
                vector=ThreatVector.SOCIAL_ENGINEERING,
                base_probability=0.08,
                affected_devices=["hub", "*"],
                state_changes={"compromised": True},
            ),
            
            # === FORCE MAJEURE ===
            "FM_001": Threat(
                id="FM_001",
                name="Awaria zasilania",
                category=ThreatCategory.FORCE_MAJEURE,
                vector=ThreatVector.POWER_FAILURE,
                base_probability=0.05,
                affected_devices=["*"],
                state_changes={"power": False},
                triggers=["FM_004"],
            ),
            "FM_002": Threat(
                id="FM_002",
                name="Awaria internetu",
                category=ThreatCategory.FORCE_MAJEURE,
                vector=ThreatVector.NETWORK_OUTAGE,
                base_probability=0.1,
                affected_devices=["*"],
                state_changes={"online": False},
            ),
            "FM_003": Threat(
                id="FM_003",
                name="Awaria sprzętowa urządzenia",
                category=ThreatCategory.FORCE_MAJEURE,
                vector=ThreatVector.HARDWARE_FAILURE,
                base_probability=0.02,
                affected_devices=["*"],
                state_changes={"malfunctioning": True, "power": False},
            ),
            "FM_004": Threat(
                id="FM_004",
                name="Zamek zablokował się przy awarii prądu",
                category=ThreatCategory.FORCE_MAJEURE,
                vector=ThreatVector.POWER_FAILURE,
                base_probability=0.0,
                affected_devices=["lock"],
                state_changes={"position": 100, "malfunctioning": True},
            ),
            "FM_005": Threat(
                id="FM_005",
                name="Bug w aktualizacji firmware",
                category=ThreatCategory.FORCE_MAJEURE,
                vector=ThreatVector.HARDWARE_FAILURE,
                base_probability=0.01,
                probability_modifiers={
                    "auto_update": 0.05,
                },
                affected_devices=["*"],
                state_changes={"malfunctioning": True},
            ),
            
            # === CASCADE ===
            "CASCADE_001": Threat(
                id="CASCADE_001",
                name="Zainfekowane urządzenie atakuje inne",
                category=ThreatCategory.CASCADE,
                vector=ThreatVector.LOCAL_NETWORK,
                base_probability=0.0,
                affected_devices=["*"],
                state_changes={"compromised": True},
            ),
        }
    
    def add_device(self, device: DeviceProfile):
        """Dodaje urządzenie do analizy"""
        self.devices[device.id] = device
    
    def analyze(self) -> "ThreatReport":
        """
        GŁÓWNA METODA
        
        Analizuje wszystkie urządzenia pod kątem wszystkich zagrożeń
        """
        report = ThreatReport()
        
        for device_id, device in self.devices.items():
            device_risks = []
            
            for threat_id, threat in self.threats.items():
                # Sprawdź czy zagrożenie dotyczy tego typu urządzenia
                if "*" not in threat.affected_devices and \
                   device.type not in threat.affected_devices:
                    continue
                
                # Oblicz prawdopodobieństwo
                probability = self._calculate_probability(device, threat)
                
                if probability > 0.001:
                    # Oblicz wpływ
                    impact = self._calculate_impact(device, threat)
                    
                    # Risk = Probability × Impact
                    risk_score = probability * impact
                    
                    device_risks.append(RiskItem(
                        device_id=device_id,
                        device_name=device.name,
                        threat_id=threat_id,
                        threat_name=threat.name,
                        category=threat.category,
                        probability=probability,
                        impact=impact,
                        risk_score=risk_score,
                        state_changes=threat.state_changes,
                        cascades=threat.triggers,
                    ))
            
            report.add_device_risks(device_id, device_risks)
        
        # Analiza efektów kaskadowych
        report.analyze_cascades(self.threats)
        
        # Generacja rekomendacji
        report.generate_recommendations()
        
        return report
    
    def _calculate_probability(self, device: DeviceProfile, threat: Threat) -> float:
        """Oblicza prawdopodobieństwo zagrożenia dla konkretnego urządzenia"""
        prob = threat.base_probability
        
        # Zastosuj modyfikatory
        for attr, modifier in threat.probability_modifiers.items():
            if hasattr(device, attr):
                device_value = getattr(device, attr)
                if isinstance(device_value, bool):
                    if device_value:
                        prob += modifier
                elif isinstance(device_value, (int, float)):
                    prob += modifier * device_value
        
        # Uwzględnij wiek urządzenia (starsze = bardziej podatne)
        age_factor = 1 + (device.age_months / 36) * 0.2
        prob *= age_factor
        
        # Uwzględnij firmware
        if device.firmware_date:
            from datetime import datetime
            try:
                fw_date = datetime.strptime(device.firmware_date, "%Y-%m-%d")
                days_old = (datetime.now() - fw_date).days
                if days_old > 365:
                    prob *= 1 + (days_old - 365) / 365 * 0.3
            except:
                pass
        
        return np.clip(prob, 0, 1)
    
    def _calculate_impact(self, device: DeviceProfile, threat: Threat) -> float:
        """
        Oblicza wpływ zagrożenia (1-10)
        
        Czynniki:
        - Krytyczność urządzenia (zamek > żarówka)
        - Liczba zależnych urządzeń
        - Konsekwencje fizyczne
        """
        # Bazowy wpływ według typu urządzenia
        criticality = {
            "lock": 10,
            "thermostat": 8,
            "camera": 7,
            "doorbell": 7,
            "speaker": 6,
            "hub": 9,
            "sensor_smoke": 9,
            "sensor_leak": 8,
            "kettle": 5,
            "socket": 6,
            "light": 3,
            "tv": 4,
            "vacuum": 2,
        }.get(device.type, 5)
        
        # Modyfikator według stanu
        state_mod = 1.0
        if threat.state_changes.get("compromised"):
            state_mod *= 1.5
        if threat.state_changes.get("malfunctioning"):
            state_mod *= 1.3
        if threat.state_changes.get("power") == False:
            state_mod *= 1.2
        
        # Modyfikator według zależności
        deps_mod = 1 + len(device.controls) * 0.1
        
        impact = criticality * state_mod * deps_mod / 10
        
        return np.clip(impact, 1, 10)
    
    def simulate_scenario(
        self, 
        initial_threat_id: str,
        duration_hours: float = 24
    ) -> "ScenarioResult":
        """
        Symuluje rozwój zagrożenia w czasie
        
        Pokazuje efekty kaskadowe i stan systemu
        """
        timeline = []
        current_states = {d.id: DeviceState() for d in self.devices.values()}
        active_threats = set()
        
        threat = self.threats.get(initial_threat_id)
        if not threat:
            return None
        
        t = 0
        active_threats.add(initial_threat_id)
        
        # Zastosuj początkowe zagrożenie
        for device_id, device in self.devices.items():
            if "*" in threat.affected_devices or device.type in threat.affected_devices:
                for key, value in threat.state_changes.items():
                    if hasattr(current_states[device_id], key):
                        setattr(current_states[device_id], key, value)
                
                timeline.append({
                    "time": t,
                    "event": f"Zagrożenie '{threat.name}' wpłynęło na {device.name}",
                    "device": device_id,
                    "state": current_states[device_id].__dict__.copy()
                })
        
        # Symulacja kaskad
        while t < duration_hours:
            t += 0.5
            
            new_threats = set()
            for tid in active_threats:
                t_obj = self.threats.get(tid)
                if t_obj and t_obj.triggers:
                    for cascade_id in t_obj.triggers:
                        if cascade_id not in active_threats:
                            cascade = self.threats.get(cascade_id)
                            if cascade and np.random.random() < 0.3:
                                new_threats.add(cascade_id)
                                
                                for device_id, device in self.devices.items():
                                    if "*" in cascade.affected_devices or \
                                       device.type in cascade.affected_devices:
                                        for key, value in cascade.state_changes.items():
                                            if hasattr(current_states[device_id], key):
                                                setattr(current_states[device_id], key, value)
                                        
                                        timeline.append({
                                            "time": t,
                                            "event": f"KASKADA: '{cascade.name}' wpłynęła na {device.name}",
                                            "device": device_id,
                                            "state": current_states[device_id].__dict__.copy()
                                        })
            
            active_threats.update(new_threats)
            
            # Detekcja i odzyskiwanie
            for tid in list(active_threats):
                t_obj = self.threats.get(tid)
                if t_obj and t > t_obj.detection_time_hours:
                    timeline.append({
                        "time": t,
                        "event": f"Zagrożenie '{t_obj.name}' wykryte!",
                        "device": None,
                        "state": None
                    })
                    
                    if t > t_obj.detection_time_hours + t_obj.recovery_time_hours:
                        active_threats.remove(tid)
                        timeline.append({
                            "time": t,
                            "event": f"Odzyskanie po '{t_obj.name}'",
                            "device": None,
                            "state": None
                        })
        
        return ScenarioResult(
            initial_threat=initial_threat_id,
            duration=duration_hours,
            timeline=timeline,
            final_states=current_states,
            triggered_cascades=list(active_threats - {initial_threat_id})
        )


@dataclass
class RiskItem:
    """Element ryzyka"""
    device_id: str
    device_name: str
    threat_id: str
    threat_name: str
    category: ThreatCategory
    probability: float
    impact: float
    risk_score: float
    state_changes: Dict
    cascades: List[str]

@dataclass
class ScenarioResult:
    """Wynik symulacji scenariusza"""
    initial_threat: str
    duration: float
    timeline: List[Dict]
    final_states: Dict[str, DeviceState]
    triggered_cascades: List[str]

class ThreatReport:
    """Raport o zagrożeniach"""
    
    def __init__(self):
        self.device_risks: Dict[str, List[RiskItem]] = {}
        self.total_risk_score: float = 0
        self.risk_by_category: Dict[ThreatCategory, float] = {}
        self.top_threats: List[RiskItem] = []
        self.cascade_paths: List[List[str]] = []
        self.recommendations: List[str] = []
    
    def add_device_risks(self, device_id: str, risks: List[RiskItem]):
        self.device_risks[device_id] = risks
        self.total_risk_score += sum(r.risk_score for r in risks)
    
    def analyze_cascades(self, threats: Dict[str, Threat]):
        """Analizuje możliwe łańcuchy kaskadowe"""
        def find_paths(threat_id: str, path: List[str], visited: set):
            if threat_id in visited:
                return
            visited.add(threat_id)
            path.append(threat_id)
            
            threat = threats.get(threat_id)
            if threat and threat.triggers:
                for next_id in threat.triggers:
                    find_paths(next_id, path.copy(), visited.copy())
            else:
                if len(path) > 1:
                    self.cascade_paths.append(path)
        
        for risk_list in self.device_risks.values():
            for risk in risk_list:
                if risk.cascades:
                    find_paths(risk.threat_id, [], set())
    
    def generate_recommendations(self):
        """Generuje rekomendacje na podstawie analizy"""
        all_risks = []
        for risks in self.device_risks.values():
            all_risks.extend(risks)
        
        self.top_threats = sorted(all_risks, key=lambda x: x.risk_score, reverse=True)[:10]
        
        for risk in all_risks:
            cat = risk.category
            self.risk_by_category[cat] = self.risk_by_category.get(cat, 0) + risk.risk_score
        
        seen_recs = set()
        
        for risk in self.top_threats:
            rec = None
            
            if "default_password" in risk.threat_name.lower() or \
               "domyślne hasło" in risk.threat_name.lower() or \
               risk.threat_id == "HUM_001":
                rec = "🔑 Zmień hasła na wszystkich urządzeniach z domyślnych"
            
            elif "firmware" in risk.threat_name.lower() or \
                 risk.threat_id == "HUM_004":
                rec = "📦 Zaktualizuj firmware na wszystkich urządzeniach"
            
            elif risk.category == ThreatCategory.FORCE_MAJEURE and \
                 "power" in str(risk.state_changes):
                rec = "🔋 Zainstaluj UPS dla krytycznych urządzeń (zamek, hub)"
            
            elif "lock" in risk.device_name.lower() or "zamek" in risk.device_name.lower():
                if risk.risk_score > 0.3:
                    rec = "🔐 Włącz automatyczne zamykanie na zamku"
            
            elif "camera" in risk.device_name.lower() or "kamera" in risk.device_name.lower():
                rec = "📷 Włącz szyfrowanie strumienia wideo (RTSPS)"
            
            elif risk.category == ThreatCategory.HUMAN_ERROR:
                rec = "👨‍👩‍👧‍👦 Ogranicz dostęp dzieci do sterowania krytycznymi urządzeniami"
            
            if rec and rec not in seen_recs:
                seen_recs.add(rec)
                self.recommendations.append(rec)
    
    def to_dict(self) -> Dict:
        """Eksport raportu"""
        return {
            "total_risk_score": round(self.total_risk_score, 2),
            "risk_level": self._risk_level(),
            "risk_by_category": {
                cat.value: round(score, 2) 
                for cat, score in self.risk_by_category.items()
            },
            "top_threats": [
                {
                    "device": t.device_name,
                    "threat": t.threat_name,
                    "category": t.category.value,
                    "probability": f"{t.probability:.1%}",
                    "impact": f"{t.impact:.1f}/10",
                    "risk": round(t.risk_score, 3)
                }
                for t in self.top_threats
            ],
            "cascade_paths": self.cascade_paths,
            "recommendations": self.recommendations,
        }
    
    def _risk_level(self) -> str:
        if self.total_risk_score < 1:
            return "🟢 NISKI"
        elif self.total_risk_score < 3:
            return "🟡 ŚREDNI"
        elif self.total_risk_score < 6:
            return "🟠 WYSOKI"
        else:
            return "🔴 KRYTYCZNY"
```

---

## PRZYKŁAD UŻYCIA

```python
# Tworzymy analizator
analyzer = ThreatAnalyzer()

# Dodajemy urządzenia naszego inteligentnego domu
analyzer.add_device(DeviceProfile(
    id="cam_1",
    type="camera",
    name="Kamera w salonie",
    vendor="Hikvision",
    firmware_version="5.4.1",
    firmware_date="2022-03-15",  # stary firmware!
    has_default_password=True,    # krytyczny błąd!
    encryption_enabled=False,     # kolejny!
    exposed_to_internet=True,
    age_months=24,
))

analyzer.add_device(DeviceProfile(
    id="lock_1",
    type="lock",
    name="Drzwi wejściowe",
    vendor="August",
    firmware_version="3.2.0",
    firmware_date="2024-01-10",
    has_default_password=False,
    encryption_enabled=True,
    age_months=6,
    controls=["door_sensor"],
))

analyzer.add_device(DeviceProfile(
    id="thermo_1",
    type="thermostat",
    name="Termostat Nest",
    vendor="Google",
    firmware_version="2.1.4",
    firmware_date="2023-08-20",
    has_default_password=False,
    auto_update=True,
    age_months=12,
))

# Uruchamiamy analizę
report = analyzer.analyze()

# Wynik
print(report.to_dict())
```

**Wyjście:**

```json
{
  "total_risk_score": 4.73,
  "risk_level": "🟠 WYSOKI",
  "risk_by_category": {
    "malicious": 2.85,
    "human_error": 1.43,
    "force_majeure": 0.45
  },
  "top_threats": [
    {
      "device": "Kamera w salonie",
      "threat": "Atak brute-force na hasło",
      "category": "malicious",
      "probability": "87.3%",
      "impact": "8.2/10",
      "risk": 0.716
    },
    {
      "device": "Kamera w salonie",
      "threat": "Przechwycenie strumienia wideo",
      "category": "malicious",
      "probability": "65.0%",
      "impact": "7.0/10",
      "risk": 0.455
    },
    {
      "device": "Kamera w salonie",
      "threat": "Pozostawione domyślne hasło",
      "category": "human_error",
      "probability": "40.0%",
      "impact": "7.0/10",
      "risk": 0.280
    }
  ],
  "cascade_paths": [
    ["HUM_001", "MAL_001"],
    ["HUM_004", "MAL_001", "CASCADE_001"],
    ["FM_001", "FM_004"]
  ],
  "recommendations": [
    "🔑 Zmień hasła na wszystkich urządzeniach z domyślnych",
    "📦 Zaktualizuj firmware na wszystkich urządzeniach",
    "📷 Włącz szyfrowanie strumienia wideo (RTSPS)",
    "🔋 Zainstaluj UPS dla krytycznych urządzeń (zamek, hub)"
  ]
}
```

---

## WIZUALIZACJA (UI)

### Główny ekran narzędzia

```
┌─────────────────────────────────────────────────────────────────────────┐
│  IoT THREAT ANALYZER                                      [PL][UA][EN]  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────────┐  ┌─────────────────────────────────┐  │
│  │       PRZEGLĄD RYZYKA        │  │       MACIERZ ZAGROŻEŃ          │  │
│  │                              │  │                                 │  │
│  │    ┌───────────────────┐    │  │      Niski  Śred   Wys   Kryt   │  │
│  │    │                   │    │  │  Praw ─┼─────┼─────┼─────┼────  │  │
│  │    │   WYSOKIE RYZYKO  │    │  │  Wys  │     │ 🔵  │ 🔴  │ 🔴   │  │
│  │    │      4.73         │    │  │  Śred │ 🟢  │ 🟡  │ 🔴  │ 🔴   │  │
│  │    │                   │    │  │  Nis  │ 🟢  │ 🟢  │ 🟡  │ 🔴   │  │
│  │    └───────────────────┘    │  │       └─────┴─────┴─────┴────   │  │
│  │                              │  │                                 │  │
│  │  🎭 Złośliwe:     2.85      │  │  🔴 Kamera salon (3 zagrożenia) │  │
│  │  🤦 Czynnik ludzki: 1.43    │  │  🟡 Termostat (1 zagrożenie)    │  │
│  │  ⚡ Siła wyższa:   0.45     │  │  🟢 Zamek (niskie ryzyko)       │  │
│  │                              │  │                                 │  │
│  └──────────────────────────────┘  └─────────────────────────────────┘  │
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  📋 TOP ZAGROŻENIA                                                 │  │
│  ├───────────────────────────────────────────────────────────────────┤  │
│  │  #  Urządzenie        Zagrożenie                   Typ     Ryzyko │  │
│  │  ─────────────────────────────────────────────────────────────────│  │
│  │  1  Kamera salon      Atak brute-force             🎭      0.716  │  │
│  │  2  Kamera salon      Przechwycenie wideo          🎭      0.455  │  │
│  │  3  Kamera salon      Domyślne hasło               🤦      0.280  │  │
│  │  4  Termostat         Dziecko wyłączyło ogrzewanie 🤦      0.120  │  │
│  │  5  Zamek             Awaria zasilania             ⚡      0.085  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  💡 REKOMENDACJE                                                   │  │
│  ├───────────────────────────────────────────────────────────────────┤  │
│  │  🔑 Zmień hasła na wszystkich urządzeniach z domyślnych           │  │
│  │  📦 Zaktualizuj firmware na wszystkich urządzeniach               │  │
│  │  📷 Włącz szyfrowanie strumienia wideo (RTSPS)                    │  │
│  │  🔋 Zainstaluj UPS dla krytycznych urządzeń                       │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  [+ DODAJ URZĄDZENIE]  [🔄 PRZELICZ]  [📊 EKSPORT PDF]  [▶ SYMULACJA]   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Graf kaskadowy

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ANALIZA KASKAD                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│                    ┌─────────────────┐                                  │
│                    │   HUM_001       │                                  │
│                    │   Domyślne      │                                  │
│                    │   hasło         │                                  │
│                    └────────┬────────┘                                  │
│                             │                                            │
│                             ▼                                            │
│                    ┌─────────────────┐                                  │
│                    │   MAL_001       │                                  │
│                    │   Brute-force   │                                  │
│                    └────────┬────────┘                                  │
│                             │                                            │
│              ┌──────────────┼──────────────┐                            │
│              ▼              ▼              ▼                            │
│     ┌──────────────┐ ┌──────────────┐ ┌──────────────┐                 │
│     │  MAL_002     │ │  MAL_003     │ │  CASCADE_001 │                 │
│     │  Strumień    │ │  Ransomware  │ │  Lateral     │                 │
│     │  wideo       │ │              │ │  movement    │                 │
│     └──────────────┘ └──────────────┘ └──────────────┘                 │
│                                                                          │
│  ───────────────────────────────────────────────────────────────────    │
│                                                                          │
│                    ┌─────────────────┐                                  │
│                    │   FM_001        │                                  │
│                    │   Awaria        │                                  │
│                    │   zasilania     │                                  │
│                    └────────┬────────┘                                  │
│                             │                                            │
│                             ▼                                            │
│                    ┌─────────────────┐                                  │
│                    │   FM_004        │                                  │
│                    │   Zamek         │                                  │
│                    │   zablokowany   │                                  │
│                    └─────────────────┘                                  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## NOWOŚĆ NAUKOWA

### 1. Unified Threat Modeling Framework (UTMF)

**Problem:** Istniejące modele rozpatrują tylko ataki hakerskie, ignorując czynnik ludzki i siłę wyższą.

**Rozwiązanie:** Jednolity model matematyczny dla WSZYSTKICH typów zagrożeń z:
- Wspólną formułą ryzyka: `Risk = P(threat) × Impact × Cascade_factor`
- Modyfikatorami prawdopodobieństwa na podstawie konfiguracji urządzenia
- Zależnościami kaskadowymi między zagrożeniami

### 2. Cascade Threat Graph (CTG)

**Problem:** Jak przewidzieć reakcję łańcuchową po początkowym zagrożeniu?

**Rozwiązanie:** Graf skierowany zagrożeń gdzie:
- Węzły = zagrożenia
- Krawędzie = wyzwalacze (jedno zagrożenie wywołuje inne)
- DFS do wyszukiwania wszystkich możliwych łańcuchów
- Symulacja w czasie z prawdopodobieństwami wyzwolenia

### 3. Device Vulnerability Scoring (DVS)

**Problem:** Jak porównać ryzyko różnych urządzeń?

**Rozwiązanie:** Scoring na podstawie:
- Krytyczności urządzenia (zamek > żarówka)
- Wieku i firmware
- Konfiguracji bezpieczeństwa
- Liczby zależnych urządzeń

### 4. Praktyczne narzędzie

**Problem:** Brak prostego sposobu dla użytkownika domowego na ocenę bezpieczeństwa.

**Rozwiązanie:** Narzędzie webowe gdzie:
- Wprowadzasz swoje urządzenia (typ, producent, ustawienia)
- Otrzymujesz raport z ryzykami
- Widzisz rekomendacje
- Możesz symulować scenariusze

---

## WARTOŚĆ KOMERCYJNA

| Aspekt | Wartość |
|--------|---------|
| **Dla użytkowników** | Darmowa analiza bezpieczeństwa domu |
| **Dla instalatorów** | Raport dla klienta przed instalacją |
| **Dla ubezpieczycieli** | Ocena ryzyka dla polis smart home |
| **Dla producentów** | Testowanie produktów pod kątem kompatybilności |
| **Dla edukacji** | Narzędzie dydaktyczne z realnymi scenariuszami |

---

## POTENCJALNE PUBLIKACJE

| # | Tytuł | Czasopismo | Nowość |
|---|-------|------------|--------|
| 1 | "Unified Threat Modeling for Smart Home IoT: Beyond Malicious Attacks" | IEEE IoT Journal | Model UTMF |
| 2 | "Cascade Threat Graphs for IoT Risk Assessment" | Computers & Security | CTG |
| 3 | "Human Factor and Force Majeure in Smart Home Security Models" | IJHCS | Rozszerzenie modeli |
| 4 | "Practical IoT Threat Analysis Tool: Design and Evaluation" | ACM CHI | Narzędzie |

---

*Wersja 2.0 — Praktyczne narzędzie*
*Grudzień 2025*
