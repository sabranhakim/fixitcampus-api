import os
from flask import Flask, jsonify, request
import redis

app = Flask(__name__)

# Konfigurasi Redis dari environment variables
redis_host = os.environ.get('REDIS_HOST', 'localhost')
redis_port = int(os.environ.get('REDIS_PORT', 6379))
# Inisialisasi koneksi Redis
try:
    r = redis.Redis(host=redis_host, port=redis_port, db=0, decode_responses=True)
    r.ping()
    print("Connected to Redis")
except redis.exceptions.ConnectionError as e:
    print(f"Could not connect to Redis: {e}")
    r = None

# Inisialisasi counter jika belum ada
if r:
    r.setnx('tickets:open', 0)
    r.setnx('tickets:closed', 0)

@app.route('/reports/summary', methods=['GET'])
def get_summary():
    """Endpoint publik untuk mendapatkan ringkasan laporan."""
    if not r:
        return jsonify({"error": "Redis service not available"}), 503
        
    open_tickets = r.get('tickets:open') or 0
    closed_tickets = r.get('tickets:closed') or 0
    
    summary = {
        "open_tickets": int(open_tickets),
        "closed_tickets": int(closed_tickets),
        "total_tickets": int(open_tickets) + int(closed_tickets)
    }
    return jsonify(summary)

@app.route('/reports/update', methods=['POST'])
def update_report():
    """Endpoint internal untuk memperbarui data laporan."""
    if not r:
        return jsonify({"error": "Redis service not available"}), 503

    data = request.get_json()
    event_type = data.get('event')
    ticket_id = data.get('ticket_id') # For logging/debugging

    if event_type == 'ticket_created':
        new_total = r.incr('tickets:open')
        print(f"INFO: Ticket {ticket_id} created. Open tickets: {new_total}")
        return jsonify({"status": "success", "open_tickets": new_total})
    elif event_type == 'ticket_updated':
        old_status = data.get('old_status')
        new_status = data.get('new_status')
        print(f"INFO: Ticket {ticket_id} updated from {old_status} to {new_status}")

        if old_status == 'open' and new_status == 'closed':
            r.decr('tickets:open')
            r.incr('tickets:closed')
            print(f"INFO: Updated counts: Open={r.get('tickets:open')}, Closed={r.get('tickets:closed')}")
        elif old_status == 'closed' and new_status == 'open':
            r.decr('tickets:closed')
            r.incr('tickets:open')
            print(f"INFO: Updated counts: Open={r.get('tickets:open')}, Closed={r.get('tickets:closed')}")
        elif old_status == 'open' and new_status == 'in_progress':
            # Optionally handle in_progress counts if needed, for now just log
            print("INFO: Ticket status changed from open to in_progress. No change to open/closed counts in summary.")
        elif old_status == 'in_progress' and new_status == 'closed':
            # If in_progress tickets are considered "open" for summary purposes
            r.decr('tickets:open')
            r.incr('tickets:closed')
            print(f"INFO: Updated counts: Open={r.get('tickets:open')}, Closed={r.get('tickets:closed')}")
        elif old_status == 'in_progress' and new_status == 'open':
            # If in_progress was treated as open, and it goes back to open, no change
            print("INFO: Ticket status changed from in_progress to open. No change to open/closed counts in summary.")
        # Add more complex transitions if your status workflow requires it
        else:
            print(f"WARNING: Unhandled status transition for ticket {ticket_id}: {old_status} -> {new_status}")

        return jsonify({"status": "success", "message": "Report updated based on ticket status change"})
    else:
        print(f"ERROR: Invalid or unhandled event type received: {event_type} for ticket {ticket_id}")
        return jsonify({"error": "Invalid event type"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
