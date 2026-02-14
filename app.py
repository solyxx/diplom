#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoT Threat Analyzer - Aplikacja webowa
Interfejs użytkownika oparty na Flask

Autor: IoT Security Research
Licencja: MIT
"""

from flask import Flask, render_template, request, jsonify, session
import json
import os
from datetime import datetime

from IoTThreatAnalyzer_v1 import (
    AnalizatorZagrozen,
    ProfilUrzadzenia,
    TYPY_URZADZEN
)
from presets import WSZYSTKIE_PRESETY, pobierz_liste_presetow, pobierz_preset

# Inicjalizacja aplikacji Flask
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Globalny analizator (dla uproszczenia - w produkcji użyłbym bazy danych)
analizator = AnalizatorZagrozen()


# ============================================================================
# STRONY GŁÓWNE
# ============================================================================

@app.route('/')
def strona_glowna():
    """Strona główna - dashboard"""
    urzadzenia = analizator.pobierz_urzadzenia()
    raport = None

    if urzadzenia:
        raport = analizator.analizuj().do_slownika()

    # Ikony dla kategorii zagrozen
    kategorie_ikony = {
        'zlosliwe': 'bi-bug',
        'blad_ludzki': 'bi-person-x',
        'sila_wyzsza': 'bi-lightning',
        'kaskada': 'bi-diagram-3'
    }

    return render_template(
        'index.html',
        urzadzenia=urzadzenia,
        typy_urzadzen=TYPY_URZADZEN,
        raport=raport,
        kategorieIkony=kategorie_ikony
    )


@app.route('/urzadzenia')
def lista_urzadzen():
    """Strona z listą urządzeń"""
    urzadzenia = analizator.pobierz_urzadzenia()
    return render_template(
        'urzadzenia.html',
        urzadzenia=urzadzenia,
        typy_urzadzen=TYPY_URZADZEN
    )


@app.route('/symulacja')
def strona_symulacji():
    """Strona symulacji scenariuszy"""
    zagrozenia = analizator.pobierz_liste_zagrozen()
    urzadzenia = analizator.pobierz_urzadzenia()
    return render_template(
        'symulacja.html',
        zagrozenia=zagrozenia,
        urzadzenia=urzadzenia,
        typy_urzadzen=TYPY_URZADZEN
    )


@app.route('/o-projekcie')
def o_projekcie():
    """Strona informacyjna o projekcie"""
    return render_template('o_projekcie.html')


@app.route('/schemat')
def schemat():
    """Strona z wizualnym schematem mieszkania"""
    return render_template('schemat.html')


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/urzadzenie', methods=['POST'])
def dodaj_urzadzenie():
    """Dodaje nowe urządzenie do analizy"""
    try:
        dane = request.json

        # Walidacja wymaganych pól
        wymagane = ['id', 'typ', 'nazwa', 'producent', 'wersja_firmware', 'data_firmware']
        for pole in wymagane:
            if pole not in dane or not dane[pole]:
                return jsonify({
                    'sukces': False,
                    'blad': f'Brak wymaganego pola: {pole}'
                }), 400

        # Tworzenie profilu urządzenia
        urzadzenie = ProfilUrzadzenia(
            id=dane['id'],
            typ=dane['typ'],
            nazwa=dane['nazwa'],
            producent=dane['producent'],
            wersja_firmware=dane['wersja_firmware'],
            data_firmware=dane['data_firmware'],
            ma_domyslne_haslo=dane.get('ma_domyslne_haslo', False),
            szyfrowanie_wlaczone=dane.get('szyfrowanie_wlaczone', True),
            auto_aktualizacja=dane.get('auto_aktualizacja', False),
            widoczne_z_internetu=dane.get('widoczne_z_internetu', False),
            automatyczne_zamykanie=dane.get('automatyczne_zamykanie', False),
            wiek_miesiace=dane.get('wiek_miesiace', 0),
        )

        analizator.dodaj_urzadzenie(urzadzenie)

        return jsonify({
            'sukces': True,
            'wiadomosc': f'Urządzenie "{urzadzenie.nazwa}" zostało dodane'
        })

    except Exception as e:
        return jsonify({
            'sukces': False,
            'blad': str(e)
        }), 500


@app.route('/api/urzadzenie/<id_urzadzenia>', methods=['DELETE'])
def usun_urzadzenie(id_urzadzenia):
    """Usuwa urządzenie z analizy"""
    try:
        analizator.usun_urzadzenie(id_urzadzenia)
        return jsonify({
            'sukces': True,
            'wiadomosc': 'Urządzenie zostało usunięte'
        })
    except Exception as e:
        return jsonify({
            'sukces': False,
            'blad': str(e)
        }), 500


@app.route('/api/urzadzenie/<id_urzadzenia>', methods=['PUT'])
def aktualizuj_urzadzenie(id_urzadzenia):
    """Aktualizuje istniejące urządzenie"""
    try:
        dane = request.json

        # Sprawdz czy urzadzenie istnieje
        if id_urzadzenia not in analizator.urzadzenia:
            return jsonify({
                'sukces': False,
                'blad': f'Nie znaleziono urzadzenia: {id_urzadzenia}'
            }), 404

        # Usun stare urzadzenie
        analizator.usun_urzadzenie(id_urzadzenia)

        # Dodaj zaktualizowane
        urzadzenie = ProfilUrzadzenia(
            id=dane['id'],
            typ=dane['typ'],
            nazwa=dane['nazwa'],
            producent=dane['producent'],
            wersja_firmware=dane['wersja_firmware'],
            data_firmware=dane['data_firmware'],
            ma_domyslne_haslo=dane.get('ma_domyslne_haslo', False),
            szyfrowanie_wlaczone=dane.get('szyfrowanie_wlaczone', True),
            auto_aktualizacja=dane.get('auto_aktualizacja', False),
            widoczne_z_internetu=dane.get('widoczne_z_internetu', False),
            automatyczne_zamykanie=dane.get('automatyczne_zamykanie', False),
            wiek_miesiace=dane.get('wiek_miesiace', 0),
        )

        analizator.dodaj_urzadzenie(urzadzenie)

        return jsonify({
            'sukces': True,
            'wiadomosc': f'Urzadzenie "{urzadzenie.nazwa}" zostalo zaktualizowane'
        })

    except Exception as e:
        return jsonify({
            'sukces': False,
            'blad': str(e)
        }), 500


@app.route('/api/analiza', methods=['GET'])
def przeprowadz_analize():
    """Przeprowadza analizę zagrożeń"""
    try:
        urzadzenia = analizator.pobierz_urzadzenia()

        if not urzadzenia:
            return jsonify({
                'sukces': False,
                'blad': 'Brak urządzeń do analizy. Dodaj co najmniej jedno urządzenie.'
            }), 400

        raport = analizator.analizuj()

        return jsonify({
            'sukces': True,
            'raport': raport.do_slownika()
        })

    except Exception as e:
        return jsonify({
            'sukces': False,
            'blad': str(e)
        }), 500


@app.route('/api/symulacja', methods=['POST'])
def uruchom_symulacje():
    """Uruchamia symulację scenariusza zagrożenia"""
    try:
        dane = request.json
        id_zagrozenia = dane.get('id_zagrozenia')
        czas_trwania = dane.get('czas_trwania', 24)

        if not id_zagrozenia:
            return jsonify({
                'sukces': False,
                'blad': 'Nie wybrano zagrożenia do symulacji'
            }), 400

        urzadzenia = analizator.pobierz_urzadzenia()
        if not urzadzenia:
            return jsonify({
                'sukces': False,
                'blad': 'Brak urządzeń do symulacji. Dodaj co najmniej jedno urządzenie.'
            }), 400

        wynik = analizator.symuluj_scenariusz(id_zagrozenia, czas_trwania)

        if not wynik:
            return jsonify({
                'sukces': False,
                'blad': 'Nie znaleziono zagrożenia o podanym ID'
            }), 404

        return jsonify({
            'sukces': True,
            'symulacja': {
                'poczatkowe_zagrozenie': wynik.poczatkowe_zagrozenie,
                'czas_trwania': wynik.czas_trwania,
                'osia_czasu': wynik.osia_czasu,
                'wyzwolone_kaskady': wynik.wyzwolone_kaskady
            }
        })

    except Exception as e:
        return jsonify({
            'sukces': False,
            'blad': str(e)
        }), 500


@app.route('/api/urzadzenia', methods=['GET'])
def pobierz_urzadzenia():
    """Zwraca listę wszystkich urządzeń"""
    urzadzenia = analizator.pobierz_urzadzenia()
    return jsonify({
        'sukces': True,
        'urzadzenia': [
            {
                'id': u.id,
                'typ': u.typ,
                'nazwa': u.nazwa,
                'producent': u.producent,
                'wersja_firmware': u.wersja_firmware,
                'data_firmware': u.data_firmware,
                'ma_domyslne_haslo': u.ma_domyslne_haslo,
                'szyfrowanie_wlaczone': u.szyfrowanie_wlaczone,
                'auto_aktualizacja': u.auto_aktualizacja,
                'widoczne_z_internetu': u.widoczne_z_internetu,
                'wiek_miesiace': u.wiek_miesiace,
            }
            for u in urzadzenia
        ]
    })


@app.route('/api/zagrozenia', methods=['GET'])
def pobierz_zagrozenia():
    """Zwraca listę wszystkich zagrożeń"""
    return jsonify({
        'sukces': True,
        'zagrozenia': analizator.pobierz_liste_zagrozen()
    })


@app.route('/api/eksport', methods=['GET'])
def eksportuj_raport():
    """Eksportuje raport do JSON"""
    try:
        urzadzenia = analizator.pobierz_urzadzenia()

        if not urzadzenia:
            return jsonify({
                'sukces': False,
                'blad': 'Brak danych do eksportu'
            }), 400

        raport = analizator.analizuj()

        eksport = {
            'data_raportu': datetime.now().isoformat(),
            'wersja': '1.0',
            'urzadzenia': [
                {
                    'id': u.id,
                    'typ': u.typ,
                    'nazwa': u.nazwa,
                    'producent': u.producent,
                }
                for u in urzadzenia
            ],
            'analiza': raport.do_slownika()
        }

        return jsonify(eksport)

    except Exception as e:
        return jsonify({
            'sukces': False,
            'blad': str(e)
        }), 500


@app.route('/api/presety', methods=['GET'])
def lista_presetow():
    """Zwraca liste dostepnych presetow"""
    return jsonify({
        'sukces': True,
        'presety': pobierz_liste_presetow()
    })


@app.route('/api/preset/<id_presetu>', methods=['POST'])
def zaladuj_preset(id_presetu):
    """Laduje wybrany preset"""
    try:
        preset = pobierz_preset(id_presetu)
        if not preset:
            return jsonify({
                'sukces': False,
                'blad': f'Nie znaleziono presetu: {id_presetu}'
            }), 404

        # Wyczysc istniejace urzadzenia
        for uid in list(analizator.urzadzenia.keys()):
            analizator.usun_urzadzenie(uid)

        # Zaladuj urzadzenia z presetu
        for urzadzenie in preset['urzadzenia']:
            analizator.dodaj_urzadzenie(urzadzenie)

        return jsonify({
            'sukces': True,
            'wiadomosc': f'Zaladowano preset "{preset["nazwa"]}" ({len(preset["urzadzenia"])} urzadzen)'
        })

    except Exception as e:
        return jsonify({
            'sukces': False,
            'blad': str(e)
        }), 500


@app.route('/api/demo', methods=['POST'])
def zaladuj_demo():
    """Ładuje przykładowe urządzenia do demonstracji"""
    try:
        # Wyczyść istniejące urządzenia
        for uid in list(analizator.urzadzenia.keys()):
            analizator.usun_urzadzenie(uid)

        # Dodaj przykładowe urządzenia
        urzadzenia_demo = [
            ProfilUrzadzenia(
                id="cam_salon",
                typ="kamera",
                nazwa="Kamera w salonie",
                producent="Hikvision",
                wersja_firmware="5.4.1",
                data_firmware="2022-03-15",
                ma_domyslne_haslo=True,
                szyfrowanie_wlaczone=False,
                widoczne_z_internetu=True,
                wiek_miesiace=24,
            ),
            ProfilUrzadzenia(
                id="cam_wejscie",
                typ="kamera",
                nazwa="Kamera przy wejściu",
                producent="Dahua",
                wersja_firmware="2.8.0",
                data_firmware="2023-06-10",
                ma_domyslne_haslo=False,
                szyfrowanie_wlaczone=True,
                widoczne_z_internetu=True,
                wiek_miesiace=12,
            ),
            ProfilUrzadzenia(
                id="zamek_glowny",
                typ="zamek",
                nazwa="Zamek drzwi wejściowych",
                producent="August",
                wersja_firmware="3.2.0",
                data_firmware="2024-01-10",
                ma_domyslne_haslo=False,
                szyfrowanie_wlaczone=True,
                automatyczne_zamykanie=True,
                wiek_miesiace=6,
            ),
            ProfilUrzadzenia(
                id="termostat_1",
                typ="termostat",
                nazwa="Termostat Nest",
                producent="Google",
                wersja_firmware="2.1.4",
                data_firmware="2023-08-20",
                ma_domyslne_haslo=False,
                auto_aktualizacja=True,
                wiek_miesiace=12,
            ),
            ProfilUrzadzenia(
                id="hub_1",
                typ="hub",
                nazwa="SmartThings Hub",
                producent="Samsung",
                wersja_firmware="1.0.5",
                data_firmware="2023-12-01",
                ma_domyslne_haslo=False,
                szyfrowanie_wlaczone=True,
                wiek_miesiace=8,
            ),
            ProfilUrzadzenia(
                id="glosnik_1",
                typ="glosnik",
                nazwa="Amazon Echo",
                producent="Amazon",
                wersja_firmware="4.0.1",
                data_firmware="2024-06-15",
                ma_domyslne_haslo=False,
                szyfrowanie_wlaczone=True,
                auto_aktualizacja=True,
                wiek_miesiace=3,
            ),
            ProfilUrzadzenia(
                id="tv_salon",
                typ="tv",
                nazwa="Smart TV Samsung",
                producent="Samsung",
                wersja_firmware="1.2.3",
                data_firmware="2023-03-01",
                ma_domyslne_haslo=False,
                szyfrowanie_wlaczone=True,
                wiek_miesiace=18,
            ),
            ProfilUrzadzenia(
                id="dzwonek_1",
                typ="dzwonek",
                nazwa="Ring Doorbell",
                producent="Ring",
                wersja_firmware="2.0.1",
                data_firmware="2024-02-20",
                ma_domyslne_haslo=False,
                szyfrowanie_wlaczone=True,
                widoczne_z_internetu=True,
                wiek_miesiace=6,
            ),
        ]

        for urzadzenie in urzadzenia_demo:
            analizator.dodaj_urzadzenie(urzadzenie)

        return jsonify({
            'sukces': True,
            'wiadomosc': f'Załadowano {len(urzadzenia_demo)} urządzeń demonstracyjnych'
        })

    except Exception as e:
        return jsonify({
            'sukces': False,
            'blad': str(e)
        }), 500


# ============================================================================
# URUCHOMIENIE APLIKACJI
# ============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("IoT THREAT ANALYZER - Starting server...")
    print("=" * 60)
    print()
    print("Open browser: http://127.0.0.1:5000")
    print()
    print("Press Ctrl+C to stop")
    print("=" * 60)

    app.run(debug=True, host='127.0.0.1', port=5000)
