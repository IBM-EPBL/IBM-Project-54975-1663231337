import binascii
import math
import random
import requests as res
import secrets
import time
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from time import strftime, localtime

import ibm_db
from clarifai_grpc.channel.clarifai_channel import ClarifaiChannel
from clarifai_grpc.grpc.api import resources_pb2, service_pb2, service_pb2_grpc
from clarifai_grpc.grpc.api.status import status_code_pb2
from cryptography.fernet import InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, render_template, request, session, redirect

from markupsafe import escape

# clarifai
YOUR_CLARIFAI_API_KEY = "xxxxxxxxxxxxxxxxxxxxxx"
YOUR_APPLICATION_ID = "xxxxxxxxxxxxxxxxxxxxxxx"
channel = ClarifaiChannel.get_json_channel()
stub = service_pb2_grpc.V2Stub(channel)
metadata = (("authorization", f"Key {YOUR_CLARIFAI_API_KEY}"),)



# rapid API
url = "https://spoonacular-recipe-food-nutrition-v1.p.rapidapi.com/recipes/parseIngredients"
querystring = {"includeNutrition": "true"}
headers = {"content-type": "application/x-www-form-urlencoded",
           "X-RapidAPI-Key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
           "X-RapidAPI-Host": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
           }

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'jfif'}

KEY = "24803877913464067088963527689231"

conn = ibm_db.connect(
    "DATABASE=bludb;HOSTNAME=fbd88901-ebdb-4a4f-a32e-9822b9fb237b.c1ogj3sd0tgtu0lqde00.databases.appdomain.cloud;PORT"
    "=32731;SECURITY=SSL;SSLServerCertificate=DigiCertGlobalRootCA.crt;UID=qxm31937;PWD=m7RdWnmWW3Y6zKiR",
    '', '')

print(conn)

app = Flask(__name__)

app.secret_key = "\xfd{H\xe5<\x95\xf9\xe3\x96.5\xd1\x01O<!\xd5\xa2\xa0\x9fR"



@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def homepage():
    if request.method == 'POST' and 'email' in request.form and 'pass' in request.form:
        error = None
        username = request.form['email']
        password = request.form['pass']
        user = None

        if username == "":
            error = 'Incorrect username.'
            return render_template('index.html', error=error)

        if password == "":
            error = 'Incorrect password.'
            return render_template('index.html', error=error)

        sql = "SELECT * FROM ADMIN WHERE email =?"
        stmt = ibm_db.prepare(conn, sql)
        ibm_db.bind_param(stmt, 1, username)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)
        if account:
            print(aes_gcm_decrypt(account['PASSWORD'], bytes(KEY, 'utf-8')))
            print(bytes(password, 'utf-8'))
            if aes_gcm_decrypt(account['PASSWORD'], bytes(KEY, 'utf-8')) == bytes(password, 'utf-8'):
                user = account['NAME']
                email = account["EMAIL"]
                session["loggedIn"] = None
                session['name'] = user
                session['email'] = email
                msg = None
                history = get_history()  # end of user

                list = get_user()
                return render_template('adminpanal.html', user=user, list=list, email=email, msg=msg)
            return render_template('index.html', error="Wrong Password!")

        sql = "SELECT * FROM USER WHERE email =?"
        stmt = ibm_db.prepare(conn, sql)
        ibm_db.bind_param(stmt, 1, username)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)
        if not account:
            return render_template('index.html', error="Username not found!")

        print(aes_gcm_decrypt(account['PASSWORD'], bytes(KEY, 'utf-8')))
        print(bytes(password, 'utf-8'))
        if aes_gcm_decrypt(account['PASSWORD'], bytes(KEY, 'utf-8')) == bytes(password, 'utf-8'):
            user = account['NAME']
            email = account["EMAIL"]
            session["loggedIn"] = 'loggedIn'
            session['name'] = user
            session['email'] = email
            msg = None
            history = get_history()  # end of user

            list = get_user()
            return render_template('dashboard.html', user=user, email=email, msg=msg, history=history)
        return render_template('index.html', error="Wrong Password!")

    elif request.method == 'POST' and 'deleteHistory' in request.form:
        sql = f"SELECT * FROM PERSON WHERE email='{session['email']}'"
        print(sql)
        stmt = ibm_db.exec_immediate(conn, sql)
        list_of_history = ibm_db.fetch_row(stmt)
        if list_of_history:
            sql = f"DELETE FROM PERSON WHERE email='{session['email']}'"
            stmt = ibm_db.exec_immediate(conn, sql)
            history = get_history()
            if history:
                return render_template("dashboard.html", msg="Delete successfully", user=session['name'],
                                       email=session['email'])

        return render_template("dashboard.html", msg="Delete successfully", user=session['name'],
                               email=session['email'])

    elif request.method == 'POST' and 'logout' in request.form:
        session["loggedIn"] = None
        session['name'] = None
        session['email'] = None
        return render_template('index.html', error="Successfully Logged Out!")

    elif request.method == 'POST' and 'extra_submit_param_view' in request.form:
        nutrition_list = request.form["extra_submit_param_view"]
        history = get_history()
        splitted_nutrition = nutrition_list.split(",")
        return render_template('dashboard.html', user=session['name'], email=session['email'], data=splitted_nutrition,
                               history=history)

    elif request.method == 'POST' and 'extra_submit_param_delete' in request.form:
        time_identity = request.form["extra_submit_param_delete"]
        history = get_history()
        sql = f"SELECT * FROM PERSON WHERE time='{escape(time_identity)}'"
        stmt = ibm_db.exec_immediate(conn, sql)
        row = ibm_db.fetch_row(stmt)
        if row:
            sql = f"DELETE FROM PERSON WHERE time='{escape(time_identity)}'"
            stmt = ibm_db.exec_immediate(conn, sql)
            history = get_history()
            if history:
                return render_template("dashboard.html", history=history, msg="Delete successfully")
            return render_template("dashboard.html", msg="Delete successfully")
        return render_template("dashboard.html", history=history, msg="Something went wrong, Try again")

    elif request.method == 'POST' and 'extra_submit_param_record' in request.form:
        email_user = request.form["extra_submit_param_record"]
        return render_template('adminpanal.html', user=session['name'], email=session['email'], list=get_user(),
                               history=get_history_person(email_user))

    elif request.method == 'POST' and 'extra_submit_param_delete_user' in request.form:
        email_user = request.form["extra_submit_param_delete_user"]
        sql = f"SELECT * FROM USER WHERE time='{escape(email_user)}'"
        stmt = ibm_db.exec_immediate(conn, sql)
        row = ibm_db.fetch_row(stmt)
        if row:
            sql = f"DELETE FROM USER WHERE time='{escape(email_user)}'"
            stmt = ibm_db.exec_immediate(conn, sql)
        sql = f"SELECT * FROM PERSON WHERE time='{escape(email_user)}'"
        stmt = ibm_db.exec_immediate(conn, sql)
        row = ibm_db.fetch_row(stmt)
        if row:
            sql = f"DELETE FROM PERSON WHERE time='{escape(email_user)}'"
            stmt = ibm_db.exec_immediate(conn, sql)
        return render_template('adminpanal.html', user=session['name'], list=get_user())

    elif request.method == 'POST' and 'extra_submit_param_nutritions' in request.form:
        user_time = request.form["extra_submit_param_nutritions"]
        user_of = get_history_person_time(user_time)
        user_dic = user_of[0]
        splitted_nutrition = user_dic['NUTRITION'].split(",")
        return render_template('adminpanal.html', user=session['name'], list=get_user(),
                               history=get_history_person(user_dic["EMAIL"]), data=splitted_nutrition)

    elif request.method == 'POST' and 'extra_submit_param_delete_record' in request.form:
        email_user = request.form["extra_submit_param_delete_record"]
        user_of = get_history_person_time(email_user)
        user_dic = user_of[0]
        sql = f"SELECT * FROM PERSON WHERE time='{escape(email_user)}'"
        stmt = ibm_db.exec_immediate(conn, sql)
        row = ibm_db.fetch_row(stmt)
        if row:
            sql = f"DELETE FROM PERSON WHERE time='{escape(email_user)}'"
            stmt = ibm_db.exec_immediate(conn, sql)
        return render_template('adminpanal.html', user=session['name'], list=get_user(),
                               history=get_history_person(user_dic["EMAIL"]))

    elif session.get('loggedIn'):
        history = get_history()
        return render_template('dashboard.html', user=session['name'], history=history)
    return render_template('index.html')


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/dashboard', methods=['GET', 'POST'])
def upload_file():
    history = []
    # sql = "SELECT * FROM Students"
    sql = f"SELECT * FROM PERSON WHERE email = '{session['email']}'"
    stmt = ibm_db.exec_immediate(conn, sql)
    dictionary = ibm_db.fetch_both(stmt)
    while dictionary:
        history.append(dictionary)
        dictionary = ibm_db.fetch_both(stmt)
    if request.method == 'POST':
        # check if the post request has the file part
        if 'logout' in request.form:
            session["loggedIn"] = None
            session['name'] = None
            session['email'] = None
            return render_template('index.html', error="Successfully created")
        if 'file' not in request.files:
            # flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.

        if file.filename == '':
            return render_template('dashboard.html', msg="File not found", history=history)
        baseimage = file.read()
        if file and allowed_file(file.filename):
            requests = service_pb2.PostModelOutputsRequest(
                # This is the model ID of a publicly available General model. You may use any other public or custom
                # model ID.
                # model_id="general-image-recognition"
                # model_id="food-item-recognition"
                model_id="food-item-recognition",
                user_app_id=resources_pb2.UserAppIDSet(app_id=YOUR_APPLICATION_ID),
                inputs=[
                    resources_pb2.Input(
                        data=resources_pb2.Data(image=resources_pb2.Image(base64=baseimage))
                    )
                ],
            )
            response = stub.PostModelOutputs(requests, metadata=metadata)

            if response.status.code != status_code_pb2.SUCCESS:
                return render_template('dashboard.html', msg=f'Failed {response.status}', history=history)

            calcium = 0
            vitaminb5 = 0
            protein = 0
            vitamind = 0
            vitamina = 0
            vitaminb2 = 0
            carbohydrates = 0
            fiber = 0
            fat = 0
            sodium = 0
            vitaminc = 0
            calories = 0
            vitaminb1 = 0
            folicacid = 0
            sugar = 0
            vitamink = 0
            cholesterol = 0
            potassium = 0
            monounsaturatedfat = 0
            polyunsaturatedfat = 0
            saturatedfat = 0
            totalfat = 0

            calciumu = 'g'
            vitaminb5u = 'g'
            proteinu = 'g'
            vitamindu = 'g'
            vitaminau = 'g'
            vitaminb2u = 'g'
            carbohydratesu = 'g'
            fiberu = 'g'
            fatu = 'g'
            sodiumu = 'g'
            vitamincu = 'g'
            caloriesu = 'cal'
            vitaminb1u = 'g'
            folicacidu = 'g'
            sugaru = 'g'
            vitaminku = 'g'
            cholesterolu = 'g'
            potassiumu = 'g'
            monounsaturatedfatu = 'g'
            polyunsaturatedfatu = 'g'
            saturatedfatu = 'g'
            totalfatu = 'g'

            for concept in response.outputs[0].data.concepts:
                print("%12s: %.2f" % (concept.name, concept.value))
                if concept.value > 0.5:
                    payload = "ingredientList=" + concept.name + "&servings=1"
                    response1 = res.request("POST", url, data=payload, headers=headers, params=querystring)
                    data = response1.json()
                    for i in range(0, 1):
                        nutri_array = data[i]
                        nutri_dic = nutri_array['nutrition']
                        nutri = nutri_dic['nutrients']

                        for z in range(0, len(nutri)):
                            temp = nutri[z]
                            if temp['name'] == 'Calcium':
                                calcium += temp['amount']
                                calciumu = temp['unit']
                            elif temp['name'] == 'Vitamin B5':
                                vitaminb5 += temp['amount']
                                vitaminb5u = temp['unit']
                            elif temp['name'] == 'Protein':
                                protein += temp['amount']
                                proteinu = temp['unit']
                            elif temp['name'] == 'Vitamin D':
                                vitamind += temp['amount']
                                vitamindu = temp['unit']
                            elif temp['name'] == 'Vitamin A':
                                vitamina += temp['amount']
                                vitaminau = temp['unit']
                            elif temp['name'] == 'Vitamin B2':
                                vitaminb2 += temp['amount']
                                vitaminb2u = temp['unit']
                            elif temp['name'] == 'Carbohydrates':
                                carbohydrates += temp['amount']
                                carbohydratesu = temp['unit']
                            elif temp['name'] == 'Fiber':
                                fiber += temp['amount']
                                fiberu = temp['unit']
                            elif temp['name'] == 'Vitamin C':
                                vitaminc += temp['amount']
                                vitamincu = temp['unit']
                            elif temp['name'] == 'Calories':
                                calories += temp['amount']
                                caloriesu = 'cal'
                            elif temp['name'] == 'Vitamin B1':
                                vitaminb1 += temp['amount']
                                vitaminb1u = temp['unit']
                            elif temp['name'] == 'Folic Acid':
                                folicacid += temp['amount']
                                folicacidu = temp['unit']
                            elif temp['name'] == 'Sugar':
                                sugar += temp['amount']
                                sugaru = temp['unit']
                            elif temp['name'] == 'Vitamin K':
                                vitamink += temp['amount']
                                vitaminku = temp['unit']
                            elif temp['name'] == 'Cholesterol':
                                cholesterol += temp['amount']
                                cholesterolu = temp['unit']
                            elif temp['name'] == 'Mono Unsaturated Fat':
                                monounsaturatedfat += temp['amount']
                                monounsaturatedfatu = temp['unit']
                            elif temp['name'] == 'Poly Unsaturated Fat':
                                polyunsaturatedfat += temp['amount']
                                polyunsaturatedfatu = temp['unit']
                            elif temp['name'] == 'Saturated Fat':
                                saturatedfat += temp['amount']
                                saturatedfatu = temp['unit']
                            elif temp['name'] == 'Fat':
                                fat += temp['amount']
                                fatu = temp['unit']
                            elif temp['name'] == 'Sodium':
                                sodium += temp['amount']
                                sodiumu = temp['unit']
                            elif temp['name'] == 'Potassium':
                                potassium += temp['amount']
                                potassiumu = temp['unit']
                            else:
                                pass

            totalfat += saturatedfat + polyunsaturatedfat + monounsaturatedfat
            data = [calories, totalfat, saturatedfat, polyunsaturatedfat, monounsaturatedfat, cholesterol, sodium,
                    potassium, sugar, protein, carbohydrates, vitamina, vitaminc, vitamind, vitaminb5, calcium]
            unit = [caloriesu, "g", saturatedfatu, polyunsaturatedfatu, monounsaturatedfatu, cholesterolu, sodiumu,
                    potassiumu, sugaru, proteinu, carbohydratesu, vitaminau, vitamincu, vitamindu, vitaminb5u, calciumu]

            to_string = "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}".format(data[0], data[1], data[2], data[3],
                                                                                 data[4],
                                                                                 data[5], data[6], data[7], data[8],
                                                                                 data[9],
                                                                                 data[10], data[11], data[12], data[13],
                                                                                 data[14], data[15])
            current_time = strftime("%a, %d %b %Y %H:%M:%S", localtime())

            sql = "SELECT * FROM PERSON"
            stmt = ibm_db.prepare(conn, sql)
            # ibm_db.bind_param(stmt, 1, session['email'])
            ibm_db.execute(stmt)
            # account = ibm_db.fetch_assoc(stmt)

            try:
                insert_sql = "INSERT INTO PERSON VALUES (?,?,?,?)"
                prep_stmt = ibm_db.prepare(conn, insert_sql)
                ibm_db.bind_param(prep_stmt, 1, session['name'])
                ibm_db.bind_param(prep_stmt, 2, session['email'])
                ibm_db.bind_param(prep_stmt, 3, to_string)
                ibm_db.bind_param(prep_stmt, 4, current_time)
                ibm_db.execute(prep_stmt)
                return render_template('dashboard.html', user=session['name'], email=session['email'], data=data,
                                       history=history, unit=unit)
            except ibm_db.stmt_error:
                print(ibm_db.stmt_error())
                return render_template('dashboard.html', msg='Something wnt wrong', user=session['name'],
                                       email=session['email'], data=data, history=history)

        return render_template('dashboard.html', history=history)
    if session['name'] is None:
        return render_template('index.html')
    return render_template('dashboard.html', user=session['name'], email=session['email'], history=history)


if __name__ == '__main__':
    app.debug = True
    app.run()
