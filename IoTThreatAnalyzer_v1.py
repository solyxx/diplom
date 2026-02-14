#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoT Threat Analyzer v1.0
Narzędzie naukowe do analizy zagrożeń inteligentnego domu

Autor: IoT Security Research
Licencja: MIT
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
import json
import random


# ============================================================================
# KATEGORIE I WEKTORY ZAGROŻEŃ
# ============================================================================

class KategoriaZagrozenia(Enum):
    """Główne kategorie zagrożeń w systemie IoT"""
    ZLOSLIWE = "zlosliwe"           # Atak złośliwy (malicious)
    BLAD_LUDZKI = "blad_ludzki"     # Czynnik ludzki (human error)
    SILA_WYZSZA = "sila_wyzsza"     # Siła wyższa (force majeure)
    KASKADA = "kaskada"             # Efekt kaskadowy (cascade)


class WektorZagrozenia(Enum):
    """Wektory ataku i źródła zagrożeń"""
    # Złośliwe
    SIEC_ZDALNA = "siec_zdalna"
    SIEC_LOKALNA = "siec_lokalna"
    DOSTEP_FIZYCZNY = "dostep_fizyczny"
    LANCUCH_DOSTAW = "lancuch_dostaw"

    # Błąd ludzki
    BLEDNA_KONFIGURACJA = "bledna_konfiguracja"
    PRZYPADKOWE_URUCHOMIENIE = "przypadkowe_uruchomienie"
    SOCJOTECHNIKA = "socjotechnika"
    ZANIEDBANIE = "zaniedbanie"

    # Siła wyższa
    AWARIA_ZASILANIA = "awaria_zasilania"
    AWARIA_SIECI = "awaria_sieci"
    AWARIA_SPRZETU = "awaria_sprzetu"
    SRODOWISKOWE = "srodowiskowe"


# ============================================================================
# STRUKTURY DANYCH
# ============================================================================

@dataclass
class StanUrzadzenia:
    """
    Reprezentuje stan urządzenia w danym momencie czasowym.
    Używane do symulacji i śledzenia zmian stanu.
    """
    zasilanie: bool = True
    online: bool = True
    skompromitowane: bool = False
    uszkodzone: bool = False

    # Parametry fizyczne (zależą od typu urządzenia)
    temperatura: Optional[float] = None      # °C
    pozycja: Optional[float] = None          # % (dla zamków, rolet)
    jasnosc: Optional[float] = None          # % (dla oświetlenia)
    przeplyw: Optional[float] = None         # l/min (dla wody)

    # Parametry sieciowe
    ruch_przychodzacy: float = 0             # bytes/sec
    ruch_wychodzacy: float = 0               # bytes/sec
    aktywne_polaczenia: int = 0


@dataclass
class Zagrozenie:
    """
    Model pojedynczego zagrożenia w systemie IoT.
    Zawiera wszystkie parametry potrzebne do analizy ryzyka.
    """
    id: str
    nazwa: str
    kategoria: KategoriaZagrozenia
    wektor: WektorZagrozenia

    # Prawdopodobieństwo
    bazowe_prawdopodobienstwo: float
    modyfikatory_prawdopodobienstwa: Dict[str, float] = field(default_factory=dict)

    # Wpływ
    dotyczace_urzadzenia: List[str] = field(default_factory=list)
    zmiany_stanu: Dict[str, Any] = field(default_factory=dict)

    # Charakterystyki czasowe
    czas_wykrycia_godziny: float = 1.0
    czas_odzyskania_godziny: float = 2.0

    # Efekty kaskadowe - ID innych zagrożeń które mogą być wyzwolone
    wyzwalacze: List[str] = field(default_factory=list)


@dataclass
class ProfilUrzadzenia:
    """
    Profil urządzenia IoT z informacjami o podatnościach.
    Używane do oceny ryzyka i dopasowania zagrożeń.
    """
    id: str
    typ: str
    nazwa: str
    producent: str
    wersja_firmware: str
    data_firmware: str

    # Parametry bezpieczeństwa
    ma_domyslne_haslo: bool = False
    szyfrowanie_wlaczone: bool = True
    auto_aktualizacja: bool = False
    widoczne_z_internetu: bool = False
    automatyczne_zamykanie: bool = False

    # Parametry niezawodności
    mtbf_godziny: float = 50000              # Mean Time Between Failures
    wiek_miesiace: int = 0

    # Zależności między urządzeniami
    zalezy_od: List[str] = field(default_factory=list)
    kontroluje: List[str] = field(default_factory=list)


@dataclass
class ElementRyzyka:
    """Pojedynczy element analizy ryzyka"""
    id_urzadzenia: str
    nazwa_urzadzenia: str
    id_zagrozenia: str
    nazwa_zagrozenia: str
    kategoria: KategoriaZagrozenia
    prawdopodobienstwo: float
    wplyw: float
    wynik_ryzyka: float
    zmiany_stanu: Dict
    kaskady: List[str]


@dataclass
class WynikScenariusza:
    """Wynik symulacji scenariusza zagrożenia"""
    poczatkowe_zagrozenie: str
    czas_trwania: float
    osia_czasu: List[Dict]
    koncowe_stany: Dict[str, StanUrzadzenia]
    wyzwolone_kaskady: List[str]


# ============================================================================
# RAPORT ZAGROŻEŃ
# ============================================================================

class RaportZagrozen:
    """
    Raport analizy zagrożeń dla systemu IoT.
    Zawiera wyniki analizy, rekomendacje i ścieżki kaskadowe.
    """

    def __init__(self):
        self.ryzyka_urzadzen: Dict[str, List[ElementRyzyka]] = {}
        self.calkowity_wynik_ryzyka: float = 0
        self.ryzyko_wg_kategorii: Dict[KategoriaZagrozenia, float] = {}
        self.top_zagrozenia: List[ElementRyzyka] = []
        self.sciezki_kaskadowe: List[List[str]] = []
        self.rekomendacje: List[str] = []

    def dodaj_ryzyka_urzadzenia(self, id_urzadzenia: str, ryzyka: List[ElementRyzyka]):
        """Dodaje listę ryzyk dla konkretnego urządzenia"""
        self.ryzyka_urzadzen[id_urzadzenia] = ryzyka
        self.calkowity_wynik_ryzyka += sum(r.wynik_ryzyka for r in ryzyka)

    def analizuj_kaskady(self, zagrozenia: Dict[str, Zagrozenie]):
        """
        Analizuje możliwe łańcuchy kaskadowe zagrożeń.
        Używa przeszukiwania w głąb (DFS) do znalezienia wszystkich ścieżek.
        """
        def znajdz_sciezki(id_zagrozenia: str, sciezka: List[str], odwiedzone: set):
            if id_zagrozenia in odwiedzone:
                return
            odwiedzone.add(id_zagrozenia)
            sciezka.append(id_zagrozenia)

            zagrozenie = zagrozenia.get(id_zagrozenia)
            if zagrozenie and zagrozenie.wyzwalacze:
                for nastepny_id in zagrozenie.wyzwalacze:
                    znajdz_sciezki(nastepny_id, sciezka.copy(), odwiedzone.copy())
            else:
                if len(sciezka) > 1:
                    self.sciezki_kaskadowe.append(sciezka)

        for lista_ryzyk in self.ryzyka_urzadzen.values():
            for ryzyko in lista_ryzyk:
                if ryzyko.kaskady:
                    znajdz_sciezki(ryzyko.id_zagrozenia, [], set())

    def generuj_rekomendacje(self):
        """
        Generuje rekomendacje bezpieczeństwa na podstawie wykrytych zagrożeń.
        Rekomendacje są priorytetyzowane według wyniku ryzyka.
        """
        wszystkie_ryzyka = []
        for ryzyka in self.ryzyka_urzadzen.values():
            wszystkie_ryzyka.extend(ryzyka)

        # Sortuj według wyniku ryzyka (malejąco)
        self.top_zagrozenia = sorted(
            wszystkie_ryzyka,
            key=lambda x: x.wynik_ryzyka,
            reverse=True
        )[:10]

        # Oblicz ryzyko według kategorii
        for ryzyko in wszystkie_ryzyka:
            kat = ryzyko.kategoria
            self.ryzyko_wg_kategorii[kat] = self.ryzyko_wg_kategorii.get(kat, 0) + ryzyko.wynik_ryzyka

        # Generuj unikalne rekomendacje
        widziane_rekomendacje = set()

        for ryzyko in self.top_zagrozenia:
            rek = None

            # Rekomendacje dotyczące haseł
            if "domyślne hasło" in ryzyko.nazwa_zagrozenia.lower() or \
               ryzyko.id_zagrozenia == "HUM_001":
                rek = "🔑 Zmień hasła na wszystkich urządzeniach z domyślnych na silne, unikalne hasła"

            # Rekomendacje dotyczące firmware
            elif "firmware" in ryzyko.nazwa_zagrozenia.lower() or \
                 ryzyko.id_zagrozenia == "HUM_004":
                rek = "📦 Zaktualizuj firmware na wszystkich urządzeniach do najnowszej wersji"

            # Rekomendacje dotyczące zasilania
            elif ryzyko.kategoria == KategoriaZagrozenia.SILA_WYZSZA and \
                 "zasilanie" in str(ryzyko.zmiany_stanu).lower():
                rek = "🔋 Zainstaluj UPS dla krytycznych urządzeń (zamek, hub, kamera)"

            # Rekomendacje dla zamków
            elif "zamek" in ryzyko.nazwa_urzadzenia.lower() or "lock" in ryzyko.nazwa_urzadzenia.lower():
                if ryzyko.wynik_ryzyka > 0.3:
                    rek = "🔐 Włącz automatyczne zamykanie na zamku i ustaw kod awaryjny"

            # Rekomendacje dla kamer
            elif "kamera" in ryzyko.nazwa_urzadzenia.lower() or "camera" in ryzyko.nazwa_urzadzenia.lower():
                rek = "📷 Włącz szyfrowanie strumienia wideo (RTSPS) i wyłącz dostęp z internetu"

            # Rekomendacje dla błędów ludzkich
            elif ryzyko.kategoria == KategoriaZagrozenia.BLAD_LUDZKI:
                if "dziec" in ryzyko.nazwa_zagrozenia.lower():
                    rek = "👨‍👩‍👧‍👦 Ogranicz dostęp dzieci do sterowania krytycznymi urządzeniami"
                elif "phishing" in ryzyko.nazwa_zagrozenia.lower() or "socjotechnik" in ryzyko.nazwa_zagrozenia.lower():
                    rek = "🛡️ Włącz uwierzytelnianie dwuskładnikowe (2FA) na wszystkich kontach"

            # Rekomendacje dla sieci
            elif "siec" in ryzyko.nazwa_zagrozenia.lower() or "internet" in ryzyko.nazwa_zagrozenia.lower():
                rek = "🌐 Skonfiguruj osobną sieć VLAN dla urządzeń IoT"

            if rek and rek not in widziane_rekomendacje:
                widziane_rekomendacje.add(rek)
                self.rekomendacje.append(rek)

        # Dodaj ogólne rekomendacje jeśli lista jest krótka
        if len(self.rekomendacje) < 3:
            ogolne = [
                "🔒 Regularnie sprawdzaj logi bezpieczeństwa urządzeń",
                "📱 Używaj tylko oficjalnych aplikacji producenta",
                "🔄 Włącz automatyczne aktualizacje gdzie to możliwe",
            ]
            for rek in ogolne:
                if rek not in widziane_rekomendacje:
                    self.rekomendacje.append(rek)
                    if len(self.rekomendacje) >= 5:
                        break

    def _poziom_ryzyka(self) -> Tuple[str, str]:
        """Określa poziom ryzyka na podstawie całkowitego wyniku"""
        if self.calkowity_wynik_ryzyka < 1:
            return "NISKI", "success"
        elif self.calkowity_wynik_ryzyka < 3:
            return "ŚREDNI", "warning"
        elif self.calkowity_wynik_ryzyka < 6:
            return "WYSOKI", "danger"
        else:
            return "KRYTYCZNY", "critical"

    def do_slownika(self) -> Dict:
        """Eksportuje raport do formatu słownikowego (JSON-kompatybilny)"""
        poziom, klasa = self._poziom_ryzyka()
        return {
            "calkowity_wynik_ryzyka": round(self.calkowity_wynik_ryzyka, 2),
            "poziom_ryzyka": poziom,
            "klasa_ryzyka": klasa,
            "ryzyko_wg_kategorii": {
                kat.value: round(wynik, 2)
                for kat, wynik in self.ryzyko_wg_kategorii.items()
            },
            "top_zagrozenia": [
                {
                    "urzadzenie": t.nazwa_urzadzenia,
                    "zagrozenie": t.nazwa_zagrozenia,
                    "kategoria": t.kategoria.value,
                    "prawdopodobienstwo": f"{t.prawdopodobienstwo:.1%}",
                    "wplyw": f"{t.wplyw:.1f}/10",
                    "ryzyko": round(t.wynik_ryzyka, 3)
                }
                for t in self.top_zagrozenia
            ],
            "sciezki_kaskadowe": self.sciezki_kaskadowe,
            "rekomendacje": self.rekomendacje,
        }


# ============================================================================
# GŁÓWNY ANALIZATOR ZAGROŻEŃ
# ============================================================================

class AnalizatorZagrozen:
    """
    Główne narzędzie do analizy zagrożeń IoT.

    Implementuje Unified Threat Modeling Framework (UTMF) - jednolity model
    matematyczny dla wszystkich typów zagrożeń: złośliwych, błędów ludzkich
    i siły wyższej.
    """

    def __init__(self):
        self.urzadzenia: Dict[str, ProfilUrzadzenia] = {}
        self.zagrozenia: Dict[str, Zagrozenie] = {}
        self._zaladuj_baze_zagrozen()

    def _zaladuj_baze_zagrozen(self):
        """
        Ładuje bazę znanych zagrożeń IoT.
        Baza zawiera zagrożenia z trzech głównych kategorii plus efekty kaskadowe.
        """
        self.zagrozenia = {
            # ================================================================
            # ZAGROŻENIA ZŁOŚLIWE (MALICIOUS)
            # ================================================================
            "MAL_001": Zagrozenie(
                id="MAL_001",
                nazwa="Atak brute-force na hasło",
                kategoria=KategoriaZagrozenia.ZLOSLIWE,
                wektor=WektorZagrozenia.SIEC_ZDALNA,
                bazowe_prawdopodobienstwo=0.3,
                modyfikatory_prawdopodobienstwa={
                    "ma_domyslne_haslo": 0.9,
                    "szyfrowanie_wlaczone": -0.5,
                    "widoczne_z_internetu": 0.4,
                },
                dotyczace_urzadzenia=["kamera", "zamek", "termostat", "glosnik", "hub"],
                zmiany_stanu={"skompromitowane": True},
                czas_wykrycia_godziny=24,
                czas_odzyskania_godziny=2,
            ),
            "MAL_002": Zagrozenie(
                id="MAL_002",
                nazwa="Przechwycenie strumienia wideo",
                kategoria=KategoriaZagrozenia.ZLOSLIWE,
                wektor=WektorZagrozenia.SIEC_ZDALNA,
                bazowe_prawdopodobienstwo=0.2,
                modyfikatory_prawdopodobienstwa={
                    "szyfrowanie_wlaczone": -0.8,
                    "widoczne_z_internetu": 0.5,
                },
                dotyczace_urzadzenia=["kamera", "dzwonek"],
                zmiany_stanu={"skompromitowane": True},
                czas_wykrycia_godziny=48,
                czas_odzyskania_godziny=1,
            ),
            "MAL_003": Zagrozenie(
                id="MAL_003",
                nazwa="Ransomware na urządzeniu Smart",
                kategoria=KategoriaZagrozenia.ZLOSLIWE,
                wektor=WektorZagrozenia.SIEC_ZDALNA,
                bazowe_prawdopodobienstwo=0.05,
                dotyczace_urzadzenia=["tv", "hub", "nas"],
                zmiany_stanu={"skompromitowane": True, "uszkodzone": True},
                wyzwalacze=["CASCADE_001"],
                czas_wykrycia_godziny=1,
                czas_odzyskania_godziny=24,
            ),
            "MAL_004": Zagrozenie(
                id="MAL_004",
                nazwa="Atak Man-in-the-Middle na komunikację",
                kategoria=KategoriaZagrozenia.ZLOSLIWE,
                wektor=WektorZagrozenia.SIEC_LOKALNA,
                bazowe_prawdopodobienstwo=0.15,
                modyfikatory_prawdopodobienstwa={
                    "szyfrowanie_wlaczone": -0.7,
                },
                dotyczace_urzadzenia=["*"],
                zmiany_stanu={"skompromitowane": True},
                czas_wykrycia_godziny=72,
            ),
            "MAL_005": Zagrozenie(
                id="MAL_005",
                nazwa="Exploitacja luki w firmware",
                kategoria=KategoriaZagrozenia.ZLOSLIWE,
                wektor=WektorZagrozenia.SIEC_ZDALNA,
                bazowe_prawdopodobienstwo=0.1,
                modyfikatory_prawdopodobienstwa={
                    "auto_aktualizacja": -0.6,
                    "widoczne_z_internetu": 0.3,
                },
                dotyczace_urzadzenia=["*"],
                zmiany_stanu={"skompromitowane": True},
                wyzwalacze=["CASCADE_001"],
            ),

            # ================================================================
            # BŁĘDY LUDZKIE (HUMAN ERROR)
            # ================================================================
            "HUM_001": Zagrozenie(
                id="HUM_001",
                nazwa="Pozostawione domyślne hasło",
                kategoria=KategoriaZagrozenia.BLAD_LUDZKI,
                wektor=WektorZagrozenia.BLEDNA_KONFIGURACJA,
                bazowe_prawdopodobienstwo=0.4,
                modyfikatory_prawdopodobienstwa={
                    "auto_aktualizacja": -0.1,
                },
                dotyczace_urzadzenia=["*"],
                wyzwalacze=["MAL_001"],
                czas_wykrycia_godziny=720,  # Może nie być wykryte przez miesiące
            ),
            "HUM_002": Zagrozenie(
                id="HUM_002",
                nazwa="Dziecko przypadkowo zmieniło ustawienia",
                kategoria=KategoriaZagrozenia.BLAD_LUDZKI,
                wektor=WektorZagrozenia.PRZYPADKOWE_URUCHOMIENIE,
                bazowe_prawdopodobienstwo=0.1,
                dotyczace_urzadzenia=["termostat", "oswietlenie", "glosnik", "tv"],
                zmiany_stanu={"temperatura": 5},
                czas_wykrycia_godziny=4,
            ),
            "HUM_003": Zagrozenie(
                id="HUM_003",
                nazwa="Zapomniał zamknąć drzwi/okna",
                kategoria=KategoriaZagrozenia.BLAD_LUDZKI,
                wektor=WektorZagrozenia.PRZYPADKOWE_URUCHOMIENIE,
                bazowe_prawdopodobienstwo=0.15,
                modyfikatory_prawdopodobienstwa={
                    "automatyczne_zamykanie": -0.9,
                },
                dotyczace_urzadzenia=["zamek", "czujnik_okna"],
                zmiany_stanu={"pozycja": 0},
                czas_wykrycia_godziny=2,
            ),
            "HUM_004": Zagrozenie(
                id="HUM_004",
                nazwa="Brak aktualizacji firmware > 2 lata",
                kategoria=KategoriaZagrozenia.BLAD_LUDZKI,
                wektor=WektorZagrozenia.ZANIEDBANIE,
                bazowe_prawdopodobienstwo=0.5,
                modyfikatory_prawdopodobienstwa={
                    "auto_aktualizacja": -0.9,
                },
                dotyczace_urzadzenia=["*"],
                wyzwalacze=["MAL_001", "MAL_002", "MAL_005"],
            ),
            "HUM_005": Zagrozenie(
                id="HUM_005",
                nazwa="Phishing - podał hasło do systemu",
                kategoria=KategoriaZagrozenia.BLAD_LUDZKI,
                wektor=WektorZagrozenia.SOCJOTECHNIKA,
                bazowe_prawdopodobienstwo=0.08,
                dotyczace_urzadzenia=["hub", "*"],
                zmiany_stanu={"skompromitowane": True},
                wyzwalacze=["CASCADE_001"],
                czas_wykrycia_godziny=48,
            ),
            "HUM_006": Zagrozenie(
                id="HUM_006",
                nazwa="Udostępnienie hasła WiFi gościom",
                kategoria=KategoriaZagrozenia.BLAD_LUDZKI,
                wektor=WektorZagrozenia.BLEDNA_KONFIGURACJA,
                bazowe_prawdopodobienstwo=0.3,
                dotyczace_urzadzenia=["*"],
                wyzwalacze=["MAL_004"],
            ),

            # ================================================================
            # SIŁA WYŻSZA (FORCE MAJEURE)
            # ================================================================
            "FM_001": Zagrozenie(
                id="FM_001",
                nazwa="Awaria zasilania w budynku",
                kategoria=KategoriaZagrozenia.SILA_WYZSZA,
                wektor=WektorZagrozenia.AWARIA_ZASILANIA,
                bazowe_prawdopodobienstwo=0.05,
                dotyczace_urzadzenia=["*"],
                zmiany_stanu={"zasilanie": False},
                wyzwalacze=["FM_004"],
                czas_wykrycia_godziny=0.01,
                czas_odzyskania_godziny=4,
            ),
            "FM_002": Zagrozenie(
                id="FM_002",
                nazwa="Awaria połączenia internetowego",
                kategoria=KategoriaZagrozenia.SILA_WYZSZA,
                wektor=WektorZagrozenia.AWARIA_SIECI,
                bazowe_prawdopodobienstwo=0.1,
                dotyczace_urzadzenia=["*"],
                zmiany_stanu={"online": False},
                czas_wykrycia_godziny=0.1,
                czas_odzyskania_godziny=8,
            ),
            "FM_003": Zagrozenie(
                id="FM_003",
                nazwa="Awaria sprzętowa urządzenia",
                kategoria=KategoriaZagrozenia.SILA_WYZSZA,
                wektor=WektorZagrozenia.AWARIA_SPRZETU,
                bazowe_prawdopodobienstwo=0.02,
                dotyczace_urzadzenia=["*"],
                zmiany_stanu={"uszkodzone": True, "zasilanie": False},
                czas_wykrycia_godziny=0.5,
                czas_odzyskania_godziny=48,
            ),
            "FM_004": Zagrozenie(
                id="FM_004",
                nazwa="Zamek zablokował się przy awarii prądu",
                kategoria=KategoriaZagrozenia.SILA_WYZSZA,
                wektor=WektorZagrozenia.AWARIA_ZASILANIA,
                bazowe_prawdopodobienstwo=0.0,  # Wyzwalane kaskadowo
                dotyczace_urzadzenia=["zamek"],
                zmiany_stanu={"pozycja": 100, "uszkodzone": True},
            ),
            "FM_005": Zagrozenie(
                id="FM_005",
                nazwa="Błąd w aktualizacji firmware",
                kategoria=KategoriaZagrozenia.SILA_WYZSZA,
                wektor=WektorZagrozenia.AWARIA_SPRZETU,
                bazowe_prawdopodobienstwo=0.01,
                modyfikatory_prawdopodobienstwa={
                    "auto_aktualizacja": 0.05,
                },
                dotyczace_urzadzenia=["*"],
                zmiany_stanu={"uszkodzone": True},
                czas_odzyskania_godziny=24,
            ),
            "FM_006": Zagrozenie(
                id="FM_006",
                nazwa="Zalanie/pożar/uderzenie pioruna",
                kategoria=KategoriaZagrozenia.SILA_WYZSZA,
                wektor=WektorZagrozenia.SRODOWISKOWE,
                bazowe_prawdopodobienstwo=0.005,
                dotyczace_urzadzenia=["*"],
                zmiany_stanu={"uszkodzone": True, "zasilanie": False},
                wyzwalacze=["FM_001"],
            ),

            # ================================================================
            # EFEKTY KASKADOWE
            # ================================================================
            "CASCADE_001": Zagrozenie(
                id="CASCADE_001",
                nazwa="Zainfekowane urządzenie atakuje inne w sieci",
                kategoria=KategoriaZagrozenia.KASKADA,
                wektor=WektorZagrozenia.SIEC_LOKALNA,
                bazowe_prawdopodobienstwo=0.0,  # Wyzwalane tylko kaskadowo
                dotyczace_urzadzenia=["*"],
                zmiany_stanu={"skompromitowane": True},
                czas_wykrycia_godziny=48,
            ),
            "CASCADE_002": Zagrozenie(
                id="CASCADE_002",
                nazwa="Utrata kontroli nad wieloma urządzeniami",
                kategoria=KategoriaZagrozenia.KASKADA,
                wektor=WektorZagrozenia.SIEC_LOKALNA,
                bazowe_prawdopodobienstwo=0.0,
                dotyczace_urzadzenia=["*"],
                zmiany_stanu={"uszkodzone": True},
            ),
        }

    def dodaj_urzadzenie(self, urzadzenie: ProfilUrzadzenia):
        """Dodaje urządzenie do analizy"""
        self.urzadzenia[urzadzenie.id] = urzadzenie

    def usun_urzadzenie(self, id_urzadzenia: str):
        """Usuwa urządzenie z analizy"""
        if id_urzadzenia in self.urzadzenia:
            del self.urzadzenia[id_urzadzenia]

    def pobierz_urzadzenia(self) -> List[ProfilUrzadzenia]:
        """Zwraca listę wszystkich urządzeń"""
        return list(self.urzadzenia.values())

    def analizuj(self) -> RaportZagrozen:
        """
        Główna metoda analizy.

        Analizuje wszystkie urządzenia pod kątem wszystkich zagrożeń,
        oblicza prawdopodobieństwa, wpływ i wynik ryzyka.

        Returns:
            RaportZagrozen: Kompletny raport analizy z rekomendacjami
        """
        raport = RaportZagrozen()

        for id_urzadzenia, urzadzenie in self.urzadzenia.items():
            ryzyka_urzadzenia = []

            for id_zagrozenia, zagrozenie in self.zagrozenia.items():
                # Sprawdź czy zagrożenie dotyczy tego typu urządzenia
                if "*" not in zagrozenie.dotyczace_urzadzenia and \
                   urzadzenie.typ not in zagrozenie.dotyczace_urzadzenia:
                    continue

                # Oblicz prawdopodobieństwo z uwzględnieniem modyfikatorów
                prawdopodobienstwo = self._oblicz_prawdopodobienstwo(urzadzenie, zagrozenie)

                if prawdopodobienstwo > 0.001:
                    # Oblicz wpływ zagrożenia
                    wplyw = self._oblicz_wplyw(urzadzenie, zagrozenie)

                    # Wynik ryzyka = Prawdopodobieństwo × Wpływ
                    wynik_ryzyka = prawdopodobienstwo * wplyw

                    ryzyka_urzadzenia.append(ElementRyzyka(
                        id_urzadzenia=id_urzadzenia,
                        nazwa_urzadzenia=urzadzenie.nazwa,
                        id_zagrozenia=id_zagrozenia,
                        nazwa_zagrozenia=zagrozenie.nazwa,
                        kategoria=zagrozenie.kategoria,
                        prawdopodobienstwo=prawdopodobienstwo,
                        wplyw=wplyw,
                        wynik_ryzyka=wynik_ryzyka,
                        zmiany_stanu=zagrozenie.zmiany_stanu,
                        kaskady=zagrozenie.wyzwalacze,
                    ))

            raport.dodaj_ryzyka_urzadzenia(id_urzadzenia, ryzyka_urzadzenia)

        # Analiza efektów kaskadowych
        raport.analizuj_kaskady(self.zagrozenia)

        # Generacja rekomendacji
        raport.generuj_rekomendacje()

        return raport

    def _oblicz_prawdopodobienstwo(
        self,
        urzadzenie: ProfilUrzadzenia,
        zagrozenie: Zagrozenie
    ) -> float:
        """
        Oblicza prawdopodobieństwo zagrożenia dla konkretnego urządzenia.

        Uwzględnia:
        - Bazowe prawdopodobieństwo zagrożenia
        - Modyfikatory zależne od konfiguracji urządzenia
        - Wiek urządzenia
        - Aktualność firmware
        """
        prob = zagrozenie.bazowe_prawdopodobienstwo

        # Zastosuj modyfikatory na podstawie atrybutów urządzenia
        for atrybut, modyfikator in zagrozenie.modyfikatory_prawdopodobienstwa.items():
            if hasattr(urzadzenie, atrybut):
                wartosc_urzadzenia = getattr(urzadzenie, atrybut)
                if isinstance(wartosc_urzadzenia, bool):
                    if wartosc_urzadzenia:
                        prob += modyfikator
                elif isinstance(wartosc_urzadzenia, (int, float)):
                    prob += modyfikator * wartosc_urzadzenia

        # Uwzględnij wiek urządzenia (starsze = bardziej podatne)
        wspolczynnik_wieku = 1 + (urzadzenie.wiek_miesiace / 36) * 0.2
        prob *= wspolczynnik_wieku

        # Uwzględnij aktualność firmware
        if urzadzenie.data_firmware:
            try:
                data_fw = datetime.strptime(urzadzenie.data_firmware, "%Y-%m-%d")
                dni_od_aktualizacji = (datetime.now() - data_fw).days
                if dni_od_aktualizacji > 365:
                    prob *= 1 + (dni_od_aktualizacji - 365) / 365 * 0.3
            except ValueError:
                pass

        # Ogranicz do zakresu [0, 1]
        return max(0.0, min(1.0, prob))

    def _oblicz_wplyw(
        self,
        urzadzenie: ProfilUrzadzenia,
        zagrozenie: Zagrozenie
    ) -> float:
        """
        Oblicza wpływ zagrożenia (skala 1-10).

        Czynniki:
        - Krytyczność typu urządzenia (zamek > żarówka)
        - Liczba zależnych urządzeń
        - Rodzaj zmian stanu (kompromitacja jest gorsza niż wyłączenie)
        """
        # Bazowy wpływ według typu urządzenia
        krytycznosc = {
            "zamek": 10,
            "hub": 9,
            "czujnik_dymu": 9,
            "termostat": 8,
            "czujnik_wycieku": 8,
            "kamera": 7,
            "dzwonek": 7,
            "glosnik": 6,
            "gniazdko": 6,
            "czajnik": 5,
            "tv": 4,
            "oswietlenie": 3,
            "odkurzacz": 2,
        }.get(urzadzenie.typ, 5)

        # Modyfikator według zmian stanu
        mod_stanu = 1.0
        if zagrozenie.zmiany_stanu.get("skompromitowane"):
            mod_stanu *= 1.5
        if zagrozenie.zmiany_stanu.get("uszkodzone"):
            mod_stanu *= 1.3
        if zagrozenie.zmiany_stanu.get("zasilanie") == False:
            mod_stanu *= 1.2

        # Modyfikator według liczby kontrolowanych urządzeń
        mod_zaleznosci = 1 + len(urzadzenie.kontroluje) * 0.1

        wplyw = krytycznosc * mod_stanu * mod_zaleznosci / 10

        # Ogranicz do zakresu [1, 10]
        return max(1.0, min(10.0, wplyw))

    def symuluj_scenariusz(
        self,
        id_poczatkowego_zagrozenia: str,
        czas_trwania_godziny: float = 24
    ) -> Optional[WynikScenariusza]:
        """
        Symuluje rozwój zagrożenia w czasie.

        Pokazuje jak początkowe zagrożenie może prowadzić do efektów kaskadowych
        i jak zmienia się stan systemu w czasie.

        Args:
            id_poczatkowego_zagrozenia: ID zagrożenia do zasymulowania
            czas_trwania_godziny: Czas trwania symulacji w godzinach

        Returns:
            WynikScenariusza z osią czasu zdarzeń lub None jeśli zagrożenie nie istnieje
        """
        osia_czasu = []
        aktualne_stany = {d.id: StanUrzadzenia() for d in self.urzadzenia.values()}
        aktywne_zagrozenia = set()

        zagrozenie = self.zagrozenia.get(id_poczatkowego_zagrozenia)
        if not zagrozenie:
            return None

        t = 0
        aktywne_zagrozenia.add(id_poczatkowego_zagrozenia)

        # Zastosuj początkowe zagrożenie
        for id_urzadzenia, urzadzenie in self.urzadzenia.items():
            if "*" in zagrozenie.dotyczace_urzadzenia or \
               urzadzenie.typ in zagrozenie.dotyczace_urzadzenia:
                for klucz, wartosc in zagrozenie.zmiany_stanu.items():
                    if hasattr(aktualne_stany[id_urzadzenia], klucz):
                        setattr(aktualne_stany[id_urzadzenia], klucz, wartosc)

                osia_czasu.append({
                    "czas": t,
                    "zdarzenie": f"Zagrożenie '{zagrozenie.nazwa}' wpłynęło na {urzadzenie.nazwa}",
                    "urzadzenie": id_urzadzenia,
                    "stan": self._stan_do_slownika(aktualne_stany[id_urzadzenia])
                })

        # Symulacja kaskad w czasie
        krok = 0.5
        while t < czas_trwania_godziny:
            t += krok

            nowe_zagrozenia = set()
            for tid in aktywne_zagrozenia:
                obiekt_zagrozenia = self.zagrozenia.get(tid)
                if obiekt_zagrozenia and obiekt_zagrozenia.wyzwalacze:
                    for id_kaskady in obiekt_zagrozenia.wyzwalacze:
                        if id_kaskady not in aktywne_zagrozenia:
                            kaskada = self.zagrozenia.get(id_kaskady)
                            if kaskada and random.random() < 0.3:
                                nowe_zagrozenia.add(id_kaskady)

                                for id_urz, urz in self.urzadzenia.items():
                                    if "*" in kaskada.dotyczace_urzadzenia or \
                                       urz.typ in kaskada.dotyczace_urzadzenia:
                                        for klucz, wartosc in kaskada.zmiany_stanu.items():
                                            if hasattr(aktualne_stany[id_urz], klucz):
                                                setattr(aktualne_stany[id_urz], klucz, wartosc)

                                        osia_czasu.append({
                                            "czas": round(t, 1),
                                            "zdarzenie": f"KASKADA: '{kaskada.nazwa}' wpłynęła na {urz.nazwa}",
                                            "urzadzenie": id_urz,
                                            "stan": self._stan_do_slownika(aktualne_stany[id_urz])
                                        })

            aktywne_zagrozenia.update(nowe_zagrozenia)

            # Detekcja zagrożeń
            for tid in list(aktywne_zagrozenia):
                obiekt_zagrozenia = self.zagrozenia.get(tid)
                if obiekt_zagrozenia and t >= obiekt_zagrozenia.czas_wykrycia_godziny:
                    # Sprawdź czy już wykryto
                    juz_wykryto = any(
                        f"'{obiekt_zagrozenia.nazwa}' wykryte" in zdarzenie.get("zdarzenie", "")
                        for zdarzenie in osia_czasu
                    )
                    if not juz_wykryto:
                        osia_czasu.append({
                            "czas": round(t, 1),
                            "zdarzenie": f"⚠️ Zagrożenie '{obiekt_zagrozenia.nazwa}' wykryte!",
                            "urzadzenie": None,
                            "stan": None
                        })

                    # Odzyskanie
                    if t >= obiekt_zagrozenia.czas_wykrycia_godziny + obiekt_zagrozenia.czas_odzyskania_godziny:
                        juz_odzyskano = any(
                            f"Odzyskanie po '{obiekt_zagrozenia.nazwa}'" in zdarzenie.get("zdarzenie", "")
                            for zdarzenie in osia_czasu
                        )
                        if not juz_odzyskano:
                            aktywne_zagrozenia.discard(tid)
                            osia_czasu.append({
                                "czas": round(t, 1),
                                "zdarzenie": f"✅ Odzyskanie po '{obiekt_zagrozenia.nazwa}'",
                                "urzadzenie": None,
                                "stan": None
                            })

        return WynikScenariusza(
            poczatkowe_zagrozenie=id_poczatkowego_zagrozenia,
            czas_trwania=czas_trwania_godziny,
            osia_czasu=osia_czasu,
            koncowe_stany=aktualne_stany,
            wyzwolone_kaskady=list(aktywne_zagrozenia - {id_poczatkowego_zagrozenia})
        )

    def _stan_do_slownika(self, stan: StanUrzadzenia) -> Dict:
        """Konwertuje stan urządzenia do słownika"""
        return {
            "zasilanie": stan.zasilanie,
            "online": stan.online,
            "skompromitowane": stan.skompromitowane,
            "uszkodzone": stan.uszkodzone,
        }

    def pobierz_liste_zagrozen(self) -> List[Dict]:
        """Zwraca listę wszystkich zagrożeń do wyświetlenia"""
        return [
            {
                "id": z.id,
                "nazwa": z.nazwa,
                "kategoria": z.kategoria.value,
                "wektor": z.wektor.value,
            }
            for z in self.zagrozenia.values()
        ]


# ============================================================================
# TYPY URZĄDZEŃ - do interfejsu użytkownika
# ============================================================================

TYPY_URZADZEN = {
    "kamera": {"nazwa": "Kamera IP", "ikona": "📷"},
    "zamek": {"nazwa": "Zamek inteligentny", "ikona": "🔐"},
    "termostat": {"nazwa": "Termostat", "ikona": "🌡️"},
    "oswietlenie": {"nazwa": "Oświetlenie", "ikona": "💡"},
    "glosnik": {"nazwa": "Głośnik inteligentny", "ikona": "🔊"},
    "tv": {"nazwa": "Smart TV", "ikona": "📺"},
    "hub": {"nazwa": "Hub/Kontroler", "ikona": "🎛️"},
    "dzwonek": {"nazwa": "Dzwonek wideo", "ikona": "🔔"},
    "czujnik_dymu": {"nazwa": "Czujnik dymu", "ikona": "🚨"},
    "czujnik_wycieku": {"nazwa": "Czujnik wycieku", "ikona": "💧"},
    "gniazdko": {"nazwa": "Inteligentne gniazdko", "ikona": "🔌"},
    "czajnik": {"nazwa": "Czajnik inteligentny", "ikona": "☕"},
    "odkurzacz": {"nazwa": "Robot odkurzający", "ikona": "🤖"},
    "nas": {"nazwa": "Serwer NAS", "ikona": "💾"},
    "router": {"nazwa": "Router", "ikona": "📡"},
}


# ============================================================================
# PRZYKŁAD UŻYCIA (uruchamiany przy bezpośrednim wywołaniu)
# ============================================================================

def przykladowa_analiza():
    """Przeprowadza przykładową analizę dla demonstracji"""
    import sys
    import io

    # Ustawienie kodowania UTF-8 dla konsoli Windows
    if sys.platform == 'win32':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

    print("=" * 70)
    print("IoT THREAT ANALYZER - Przykladowa analiza")
    print("=" * 70)
    print()

    # Tworzenie analizatora
    analizator = AnalizatorZagrozen()

    # Dodawanie urządzeń przykładowego inteligentnego domu
    analizator.dodaj_urzadzenie(ProfilUrzadzenia(
        id="cam_1",
        typ="kamera",
        nazwa="Kamera w salonie",
        producent="Hikvision",
        wersja_firmware="5.4.1",
        data_firmware="2022-03-15",  # Stary firmware!
        ma_domyslne_haslo=True,       # Krytyczny błąd!
        szyfrowanie_wlaczone=False,   # Kolejny błąd!
        widoczne_z_internetu=True,
        wiek_miesiace=24,
    ))

    analizator.dodaj_urzadzenie(ProfilUrzadzenia(
        id="lock_1",
        typ="zamek",
        nazwa="Zamek drzwi wejściowych",
        producent="August",
        wersja_firmware="3.2.0",
        data_firmware="2024-01-10",
        ma_domyslne_haslo=False,
        szyfrowanie_wlaczone=True,
        automatyczne_zamykanie=True,
        wiek_miesiace=6,
        kontroluje=["czujnik_drzwi"],
    ))

    analizator.dodaj_urzadzenie(ProfilUrzadzenia(
        id="thermo_1",
        typ="termostat",
        nazwa="Termostat Nest",
        producent="Google",
        wersja_firmware="2.1.4",
        data_firmware="2023-08-20",
        ma_domyslne_haslo=False,
        auto_aktualizacja=True,
        wiek_miesiace=12,
    ))

    analizator.dodaj_urzadzenie(ProfilUrzadzenia(
        id="hub_1",
        typ="hub",
        nazwa="SmartThings Hub",
        producent="Samsung",
        wersja_firmware="1.0.5",
        data_firmware="2023-12-01",
        ma_domyslne_haslo=False,
        szyfrowanie_wlaczone=True,
        wiek_miesiace=8,
        kontroluje=["cam_1", "lock_1", "thermo_1"],
    ))

    # Uruchomienie analizy
    print("Analizowanie systemu...")
    print()
    raport = analizator.analizuj()

    # Wyświetlenie wyników
    wynik = raport.do_slownika()

    print(f"CAŁKOWITY WYNIK RYZYKA: {wynik['calkowity_wynik_ryzyka']}")
    print(f"POZIOM RYZYKA: {wynik['poziom_ryzyka']}")
    print()

    print("RYZYKO WEDŁUG KATEGORII:")
    for kat, wartosc in wynik['ryzyko_wg_kategorii'].items():
        print(f"  • {kat}: {wartosc}")
    print()

    print("TOP ZAGROŻENIA:")
    for i, z in enumerate(wynik['top_zagrozenia'][:5], 1):
        print(f"  {i}. {z['urzadzenie']} - {z['zagrozenie']}")
        print(f"     Prawdopodobieństwo: {z['prawdopodobienstwo']}, Wpływ: {z['wplyw']}, Ryzyko: {z['ryzyko']}")
    print()

    print("REKOMENDACJE:")
    for rek in wynik['rekomendacje']:
        print(f"  {rek}")
    print()

    print("ŚCIEŻKI KASKADOWE:")
    for sciezka in wynik['sciezki_kaskadowe'][:3]:
        print(f"  {' → '.join(sciezka)}")
    print()

    # Symulacja scenariusza
    print("=" * 70)
    print("SYMULACJA SCENARIUSZA: Atak brute-force (MAL_001)")
    print("=" * 70)

    wynik_symulacji = analizator.symuluj_scenariusz("MAL_001", 48)
    if wynik_symulacji:
        for zdarzenie in wynik_symulacji.osia_czasu[:10]:
            print(f"  [{zdarzenie['czas']}h] {zdarzenie['zdarzenie']}")
        if len(wynik_symulacji.osia_czasu) > 10:
            print(f"  ... i {len(wynik_symulacji.osia_czasu) - 10} więcej zdarzeń")


if __name__ == "__main__":
    przykladowa_analiza()
