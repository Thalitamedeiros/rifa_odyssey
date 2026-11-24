import os, json, secrets, csv, io
from datetime import datetime, date
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for, flash,
                   session, abort, Response)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, UniqueConstraint

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "troque-esta-chave"),
    SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///odyssey.db")
        .replace("postgres://", "postgresql://", 1),
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
db = SQLAlchemy(app)
lm = LoginManager(app); lm.login_view = "login"
lm.login_message = "Faça login para continuar."

# ---------- Modelos ----------
class User(UserMixin, db.Model):  # usuário = membro da equipe
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    ativo = db.Column(db.Boolean, default=True)

class Rifa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    descricao = db.Column(db.Text, default="")
    imagem_url = db.Column(db.String(300), default="")
    valor = db.Column(db.Numeric(10, 2), nullable=False)
    total_numeros = db.Column(db.Integer, nullable=False)
    data_sorteio = db.Column(db.Date)
    status = db.Column(db.String(10), default="ativa")  # ativa|encerrada|sorteada
    vendas = db.relationship("Venda", backref="rifa", cascade="all, delete-orphan")
    sorteios = db.relationship("Sorteio", backref="rifa", cascade="all, delete-orphan")

class Venda(db.Model):  # inclui o comprador (dados pessoais protegidos por rota)
    id = db.Column(db.Integer, primary_key=True)
    rifa_id = db.Column(db.Integer, db.ForeignKey("rifa.id"), nullable=False)
    numero = db.Column(db.Integer, nullable=False)
    ponto = db.Column(db.String(20))
    comprador = db.Column(db.String(150), nullable=False)
    endereco = db.Column(db.String(250), nullable=False)
    telefone = db.Column(db.String(30), nullable=False)
    vendedor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    vendedor = db.relationship("User")
    data_venda = db.Column(db.Date, default=date.today)
    pagamento = db.Column(db.String(10), default="pendente")  # pendente|pago
    __table_args__ = (UniqueConstraint("rifa_id", "numero", name="uq_rifa_numero"),)

class Sorteio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rifa_id = db.Column(db.Integer, db.ForeignKey("rifa.id"), nullable=False)
    venda_id = db.Column(db.Integer, db.ForeignKey("venda.id"), nullable=False)
    venda = db.relationship("Venda")
    numero = db.Column(db.Integer, nullable=False)
    elegiveis = db.Column(db.Text, nullable=False)  # JSON p/ auditoria
    realizado_por_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    realizado_por = db.relationship("User")
    em = db.Column(db.DateTime, default=datetime.now)
    ativo = db.Column(db.Boolean, default=True)  # False = anulado por novo sorteio
    motivo = db.Column(db.String(250))

@lm.user_loader
def load_user(uid): return db.session.get(User, int(uid))

# ---------- Segurança ----------
def admin_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if not current_user.is_admin: abort(403)
        return f(*a, **k)
    return w

@app.before_request
def csrf_check():
    if request.method == "POST":
        if not session.get("_csrf") or request.form.get("_csrf") != session["_csrf"]:
            abort(400, "Token CSRF inválido.")

@app.context_processor
def ctx():
    if "_csrf" not in session: session["_csrf"] = secrets.token_hex(16)
    rifas = Rifa.query.order_by(Rifa.id).all() if current_user.is_authenticated else []
    return dict(csrf=lambda: session["_csrf"], abas=rifas)

# ---------- Autenticação ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = User.query.filter_by(email=request.form["email"].strip().lower()).first()
        if u and u.ativo and check_password_hash(u.senha_hash, request.form["senha"]):
            login_user(u); return redirect(request.args.get("next") or url_for("inicio"))
        flash("E-mail ou senha inválidos.", "erro")
    return render_template("login.html")

@app.post("/logout")
def logout():
    logout_user(); return redirect(url_for("login"))

# ---------- Início ----------
def stats(r):
    v = len(r.vendas); pagos = sum(1 for x in r.vendas if x.pagamento == "pago")
    return dict(vendidos=v, pagos=pagos, disp=r.total_numeros - v,
                pct=round(100 * v / r.total_numeros, 1) if r.total_numeros else 0,
                arrecadado=float(r.valor) * pagos)

@app.route("/")
@login_required
def inicio():
    rifas = Rifa.query.order_by(Rifa.id).all()
    st = {r.id: stats(r) for r in rifas}
    tot = dict(rifas=len(rifas), vendidos=sum(s["vendidos"] for s in st.values()),
               disp=sum(s["disp"] for s in st.values()),
               arrecadado=sum(s["arrecadado"] for s in st.values()),
               membros=User.query.filter_by(ativo=True).count(),
               andamento=sum(1 for r in rifas if r.status == "ativa"))
    ult = Sorteio.query.filter_by(ativo=True).order_by(Sorteio.em.desc()).limit(5).all()
    return render_template("index.html", rifas=rifas, st=st, tot=tot, ult=ult)

# ---------- Rifas ----------
@app.route("/rifas")
@login_required
def rifas():
    r = Rifa.query.order_by(Rifa.id).first()
    return redirect(url_for("rifa", rid=r.id)) if r else redirect(url_for("nova_rifa"))

@app.route("/rifa/nova", methods=["GET", "POST"])
@admin_required
def nova_rifa():
    if request.method == "POST":
        f = request.form
        try:
            valor = float(f["valor"].replace(",", ".")); total = int(f["total"])
            assert valor > 0 and total > 0 and f["nome"].strip()
            dt = datetime.strptime(f["data"], "%Y-%m-%d").date() if f["data"] else None
        except Exception:
            flash("Preencha nome, valor e quantidade corretamente.", "erro")
            return render_template("rifa_form.html")
        r = Rifa(nome=f["nome"].strip(), descricao=f["descricao"], imagem_url=f["imagem"],
                 valor=valor, total_numeros=total, data_sorteio=dt)
        db.session.add(r); db.session.commit()
        flash("Rifa criada!", "ok"); return redirect(url_for("rifa", rid=r.id))
    return render_template("rifa_form.html")

@app.route("/rifa/<int:rid>")
@login_required
def rifa(rid):
    r = db.session.get(Rifa, rid) or abort(404)
    q = Venda.query.filter_by(rifa_id=rid)
    if not current_user.is_admin:  # membro vê só as próprias vendas
        q = q.filter_by(vendedor_id=current_user.id)
    busca = request.args.get("q", "").strip()
    if busca:
        like = f"%{busca}%"
        q = q.join(User, Venda.vendedor_id == User.id).filter(db.or_(
            Venda.comprador.ilike(like), Venda.endereco.ilike(like), Venda.telefone.ilike(like),
            Venda.ponto.ilike(like), User.nome.ilike(like), db.cast(Venda.numero, db.String).like(like)))
    vendas = q.order_by(Venda.numero).all()
    usados = {n for (n,) in db.session.query(Venda.numero).filter_by(rifa_id=rid)}
    livres = [n for n in range(1, r.total_numeros + 1) if n not in usados]
    sorteio = Sorteio.query.filter_by(rifa_id=rid, ativo=True).first()
    return render_template("rifa.html", r=r, s=stats(r), vendas=vendas, busca=busca,
                           livres=livres[:300], n_livres=len(livres), sorteio=sorteio,
                           membros=User.query.filter_by(ativo=True).order_by(User.nome).all())

@app.post("/rifa/<int:rid>/status")
@admin_required
def rifa_status(rid):
    r = db.session.get(Rifa, rid) or abort(404)
    if request.form["status"] in ("ativa", "encerrada") and r.status != "sorteada":
        r.status = request.form["status"]; db.session.commit(); flash("Status atualizado.", "ok")
    return redirect(url_for("rifa", rid=rid))

@app.post("/rifa/<int:rid>/excluir")
@admin_required
def rifa_excluir(rid):
    r = db.session.get(Rifa, rid) or abort(404)
    db.session.delete(r); db.session.commit(); flash("Rifa excluída.", "ok")
    return redirect(url_for("rifas"))

# ---------- Vendas ----------
@app.post("/rifa/<int:rid>/venda")
@login_required
def venda_nova(rid):
    r = db.session.get(Rifa, rid) or abort(404)
    f = request.form
    if r.status != "ativa":
        flash("Esta rifa não está ativa.", "erro"); return redirect(url_for("rifa", rid=rid))
    try:
        n = int(f["numero"]); assert 1 <= n <= r.total_numeros
        assert all(f[k].strip() for k in ("comprador", "endereco", "telefone"))
        assert sum(c.isdigit() for c in f["telefone"]) >= 10
    except Exception:
        flash(f"Dados inválidos (número entre 1 e {r.total_numeros}, telefone com DDD).", "erro")
        return redirect(url_for("rifa", rid=rid))
    vend = current_user.id
    if current_user.is_admin and f.get("vendedor"): vend = int(f["vendedor"])
    if Venda.query.filter_by(rifa_id=rid, numero=n).first():
        flash(f"O número {n} já foi vendido nesta rifa.", "erro"); return redirect(url_for("rifa", rid=rid))
    pag = f.get("pagamento") if f.get("pagamento") in ("pendente", "pago") else "pendente"
    db.session.add(Venda(rifa_id=rid, numero=n, ponto=f["ponto"].strip(), comprador=f["comprador"].strip(),
                         endereco=f["endereco"].strip(), telefone=f["telefone"].strip(),
                         vendedor_id=vend, pagamento=pag))
    try: db.session.commit(); flash(f"Número {n} registrado!", "ok")
    except Exception:
        db.session.rollback(); flash("Número já vendido (conflito).", "erro")
    return redirect(url_for("rifa", rid=rid))

@app.post("/venda/<int:vid>/pagamento")
@admin_required
def venda_pagamento(vid):
    v = db.session.get(Venda, vid) or abort(404)
    if Sorteio.query.filter_by(rifa_id=v.rifa_id, ativo=True).first():
        flash("Rifa já sorteada: venda bloqueada.", "erro")
    else:
        v.pagamento = "pago" if v.pagamento == "pendente" else "pendente"
        db.session.commit(); flash("Pagamento atualizado.", "ok")
    return redirect(url_for("rifa", rid=v.rifa_id))

@app.post("/venda/<int:vid>/excluir")
@admin_required
def venda_excluir(vid):
    v = db.session.get(Venda, vid) or abort(404)
    if Sorteio.query.filter_by(venda_id=vid).first():
        flash("Venda vinculada a um sorteio não pode ser excluída.", "erro")
    else:
        db.session.delete(v); db.session.commit(); flash("Venda excluída.", "ok")
    return redirect(url_for("rifa", rid=v.rifa_id))

# ---------- Sorteio ----------
@app.post("/rifa/<int:rid>/sortear")
@admin_required
def sortear(rid):
    r = db.session.get(Rifa, rid) or abort(404)
    ant = Sorteio.query.filter_by(rifa_id=rid, ativo=True).first()
    motivo = request.form.get("motivo", "").strip()
    if ant and len(motivo) < 5:
        flash("Rifa já sorteada. Informe o motivo (mín. 5 caracteres) para refazer.", "erro")
        return redirect(url_for("rifa", rid=rid))
    elegiveis = Venda.query.filter_by(rifa_id=rid, pagamento="pago").all()  # só desta rifa
    if not elegiveis:
        flash("Não há números vendidos com pagamento confirmado.", "erro")
        return redirect(url_for("rifa", rid=rid))
    v = secrets.SystemRandom().choice(elegiveis)  # aleatoriedade segura no servidor
    if ant: ant.ativo = False
    db.session.add(Sorteio(rifa_id=rid, venda_id=v.id, numero=v.numero, realizado_por_id=current_user.id,
                           elegiveis=json.dumps(sorted(x.numero for x in elegiveis)), motivo=motivo or None))
    r.status = "sorteada"; db.session.commit()
    flash(f"Sorteio realizado! Número sorteado: {v.numero}", "ok")
    return redirect(url_for("rifa", rid=rid))

@app.route("/sorteios")
@login_required
def sorteios():
    ss = Sorteio.query.order_by(Sorteio.em.desc()).all()
    return render_template("sorteios.html", ss=ss)

# ---------- Membros ----------
@app.route("/membros", methods=["GET", "POST"])
@admin_required
def membros():
    if request.method == "POST":
        f = request.form; email = f["email"].strip().lower()
        if not f["nome"].strip() or "@" not in email or len(f["senha"]) < 6:
            flash("Informe nome, e-mail válido e senha (mín. 6).", "erro")
        elif User.query.filter_by(email=email).first():
            flash("E-mail já cadastrado.", "erro")
        else:
            db.session.add(User(nome=f["nome"].strip(), email=email, is_admin=bool(f.get("admin")),
                                senha_hash=generate_password_hash(f["senha"])))
            db.session.commit(); flash("Membro cadastrado.", "ok")
    ms = User.query.order_by(User.nome).all()
    cont = dict(db.session.query(Venda.vendedor_id, func.count(Venda.id)).group_by(Venda.vendedor_id).all())
    return render_template("membros.html", ms=ms, cont=cont)

@app.post("/membros/<int:uid>/ativo")
@admin_required
def membro_ativo(uid):
    u = db.session.get(User, uid) or abort(404)
    if u.id != current_user.id:
        u.ativo = not u.ativo; db.session.commit()
    return redirect(url_for("membros"))

# ---------- Relatórios ----------
@app.route("/relatorios")
@admin_required
def relatorios():
    rifas = Rifa.query.order_by(Rifa.id).all()
    por_membro = (db.session.query(User.nome, func.count(Venda.id))
                  .outerjoin(Venda, Venda.vendedor_id == User.id).group_by(User.id).all())
    return render_template("relatorios.html", rifas=rifas, st={r.id: stats(r) for r in rifas},
                           por_membro=por_membro, total=sum(stats(r)["arrecadado"] for r in rifas))

@app.route("/relatorios/vendas.csv")
@admin_required
def exportar():
    out = io.StringIO(); w = csv.writer(out, delimiter=";")
    w.writerow(["Rifa", "Número", "Ponto", "Comprador", "Vendedor", "Endereço", "Telefone", "Data", "Pagamento"])
    for v in Venda.query.order_by(Venda.rifa_id, Venda.numero):
        w.writerow([v.rifa.nome, v.numero, v.ponto, v.comprador, v.vendedor.nome, v.endereco,
                    v.telefone, v.data_venda, v.pagamento])
    return Response("\ufeff" + out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=vendas_odyssey.csv"})

# ---------- CLI ----------
@app.cli.command("criar-admin")
def criar_admin():
    """Cria as tabelas e o administrador inicial."""
    db.create_all()
    nome = input("Nome: "); email = input("E-mail: ").lower(); senha = input("Senha: ")
    db.session.add(User(nome=nome, email=email, is_admin=True, senha_hash=generate_password_hash(senha)))
    db.session.commit(); print("Admin criado.")

def iniciar():
    """Cria as tabelas e, se ADMIN_EMAIL/ADMIN_SENHA existirem, o primeiro administrador."""
    db.create_all()
    em, sn = os.environ.get("ADMIN_EMAIL", "").strip().lower(), os.environ.get("ADMIN_SENHA", "")
    if em and sn and not User.query.filter_by(email=em).first():
        db.session.add(User(nome=os.environ.get("ADMIN_NOME", "Administrador"), email=em,
                            is_admin=True, senha_hash=generate_password_hash(sn)))
        db.session.commit()

with app.app_context(): iniciar()
if __name__ == "__main__": app.run(debug=False)
