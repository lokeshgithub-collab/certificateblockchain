import hashlib, json, time, os
from dataclasses import dataclass, asdict
from typing import List, Optional

DATA_FILE = "chain.json"

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

@dataclass
class Certificate:
    cert_id: str
    student_name: str
    program: str
    issued_on: str
    issuer: str
    status: str
    remarks: str = ""

    def serialize(self) -> str:
        payload = {
            "cert_id": self.cert_id,
            "student_name": self.student_name,
            "program": self.program,
            "issued_on": self.issued_on,
            "issuer": self.issuer,
            "status": self.status,
            "remarks": self.remarks,
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)

@dataclass
class Block:
    index: int
    timestamp: float
    data: dict
    prev_hash: str
    nonce: int = 0

    def hash(self) -> str:
        body = {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "prev_hash": self.prev_hash,
            "nonce": self.nonce,
        }
        return sha256(json.dumps(body, separators=(",", ":"), sort_keys=True))

class Blockchain:
    def __init__(self):
        self.chain: List[Block] = []
        self.load() or self._create_genesis()

    def _create_genesis(self):
        genesis = Block(
            index=0,
            timestamp=time.time(),
            data={"type": "GENESIS", "msg": "Certificate Ledger Genesis"},
            prev_hash="0"*64,
        )
        self.chain = [genesis]
        self.save()

    def last_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, data: dict) -> Block:
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            data=data,
            prev_hash=self.last_block().hash()
        )
        while not new_block.hash().startswith("00"):
            new_block.nonce += 1
        self.chain.append(new_block)
        self.save()
        return new_block

    def is_valid(self) -> bool:
        if not self.chain:
            return False
        for i in range(1, len(self.chain)):
            cur = self.chain[i]
            prev = self.chain[i-1]
            if cur.prev_hash != prev.hash():
                return False
            if not cur.hash().startswith("00"):
                return False
        return True

    def save(self):
        with open(DATA_FILE, "w") as f:
            out = [asdict(b) for b in self.chain]
            json.dump(out, f, indent=2)

    def load(self) -> bool:
        if not os.path.exists(DATA_FILE):
            return False
        with open(DATA_FILE, "r") as f:
            raw = json.load(f)
            self.chain = [Block(**b) for b in raw]
        return True

    def find_latest_certificate(self, cert_id: str) -> Optional[Certificate]:
        for b in reversed(self.chain):
            if b.data.get("type") in ("ISSUE", "REVOKE"):
                c = b.data["certificate"]
                if c["cert_id"] == cert_id:
                    return Certificate(**c)
        return None

    def issue_certificate(self, c: Certificate) -> str:
        existing = self.find_latest_certificate(c.cert_id)
        if existing and existing.status == "ISSUED":
            return f"[X] Certificate {c.cert_id} already ISSUED."
        data = {"type": "ISSUE", "certificate": json.loads(c.serialize())}
        blk = self.add_block(data)
        return f"[✓] Issued {c.cert_id} in block #{blk.index} (hash starts with '00')."

    def revoke_certificate(self, cert_id: str, issuer: str, remarks: str) -> str:
        current = self.find_latest_certificate(cert_id)
        if not current:
            return f"[X] Certificate {cert_id} not found."
        if current.status == "REVOKED":
            return f"[X] Certificate {cert_id} already REVOKED."
        revoked = Certificate(
            cert_id=cert_id,
            student_name=current.student_name,
            program=current.program,
            issued_on=current.issued_on,
            issuer=issuer,
            status="REVOKED",
            remarks=remarks
        )
        data = {"type": "REVOKE", "certificate": json.loads(revoked.serialize())}
        blk = self.add_block(data)
        return f"[✓] Revoked {cert_id} in block #{blk.index}."

    def verify_certificate(self, cert_id: str) -> str:
        c = self.find_latest_certificate(cert_id)
        if not c:
            return f"[?] {cert_id} not found in ledger."
        for b in reversed(self.chain):
            if b.data.get("type") in ("ISSUE", "REVOKE"):
                cc = b.data["certificate"]
                if cc["cert_id"] == cert_id:
                    ok_link = b.prev_hash == self.chain[b.index-1].hash() if b.index > 0 else True
                    ok_pow = b.hash().startswith("00")
                    state = f"VALID LINK={ok_link}, POW={ok_pow}"
                    return f"[INFO] {cert_id}: status={cc['status']} (issuer={cc['issuer']}). {state}."
        return f"[?] {cert_id} not found in ledger."

def menu():
    bc = Blockchain()
    while True:
        print("\n--- Certificate Verification Ledger ---")
        print("1) Issue certificate")
        print("2) Revoke certificate")
        print("3) Verify certificate")
        print("4) Show chain length & validity")
        print("5) List last N blocks")
        print("0) Exit")
        choice = input("Select: ").strip()

        if choice == "1":
            cert_id = input("Certificate ID: ").strip()
            student = input("Student name: ").strip()
            program = input("Program: ").strip()
            issued_on = input("Issued on (YYYY-MM-DD): ").strip()
            issuer = input("Issuer (University/Dept): ").strip()
            msg = bc.issue_certificate(Certificate(cert_id, student, program, issued_on, issuer, "ISSUED"))
            print(msg)

        elif choice == "2":
            cert_id = input("Certificate ID to revoke: ").strip()
            issuer = input("Issuer confirming revocation: ").strip()
            remarks = input("Reason/remarks: ").strip()
            print(bc.revoke_certificate(cert_id, issuer, remarks))

        elif choice == "3":
            cert_id = input("Certificate ID to verify: ").strip()
            print(bc.verify_certificate(cert_id))

        elif choice == "4":
            print(f"Blocks: {len(bc.chain)} | Valid: {bc.is_valid()}")

        elif choice == "5":
            try:
                n = int(input("How many recent blocks? ").strip())
            except ValueError:
                n = 5
            for b in bc.chain[-n:]:
                print(f"#{b.index} ts={int(b.timestamp)} prev[:8]={b.prev_hash[:8]} nonce={b.nonce}")
                print(f"   type={b.data.get('type')}")
                if b.data.get("type") in ("ISSUE","REVOKE"):
                    c = b.data["certificate"]
                    print(f"   cert_id={c['cert_id']} status={c['status']} student={c['student_name']}")
        elif choice == "0":
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    menu()
