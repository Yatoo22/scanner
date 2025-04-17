import asyncio
import os
import logging
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional, Set
from aiogram import Bot, Dispatcher, types
from aiogram.types import InputFile, FSInputFile, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.filters import Command
from aiogram import F
from aiogram.exceptions import TelegramAPIError

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class Config:
    BOT_TOKEN = "6863982081:AAF-Xa7S_OgJ5TRYT_Qth_wyQ7AdjuX_eGM"
    OWNER_ID = 5264219629
    MAX_CONCURRENT_SCANS = 3
    SCAN_TIMEOUT = 36000  # 10 hour
    MAX_FILE_SIZE = 10240 * 10240  # 10MB
    SCAN_RATES = {
        "slow": 1000,
        "normal": 10000,
        "fast": 100000
    }

class UserState:
    def __init__(self):
        self.file_path: Optional[str] = None
        self.result_file: Optional[str] = None
        self.cancel: bool = False
        self.ports: Set[int] = set()
        self.scan_rate: str = "normal"
        self.active_scans: int = 0
        self.current_processes: List[asyncio.subprocess.Process] = []

def is_valid_ip_range(ip_range: str) -> bool:
    try:
        # Check CIDR format (e.g., 12.0.0.0/8)
        if '/' in ip_range:
            ipaddress.ip_network(ip_range, strict=False)
            return True
        
        # Check range format (e.g., 12.0.0.0-16.0.0.0)
        if '-' in ip_range:
            start_ip, end_ip = ip_range.split('-')
            ipaddress.ip_address(start_ip.strip())
            ipaddress.ip_address(end_ip.strip())
            return True
        
        # Check single IP format (e.g., 12.0.0.0)
        ipaddress.ip_address(ip_range)
        return True
        
    except ValueError:
        return False

class ScannerBot:
    def __init__(self):
        self.bot = Bot(token=Config.BOT_TOKEN)
        self.dp = Dispatcher()
        self.sudo_users: List[int] = [Config.OWNER_ID]
        self.user_states: Dict[int, UserState] = {}
        self.setup_handlers()

    def setup_handlers(self):
        self.dp.message.register(self.start_cmd, Command("start"))
        self.dp.message.register(self.help_cmd, Command("help"))
        self.dp.message.register(self.status_cmd, Command("status"))
        self.dp.message.register(self.cancel_cmd, Command("cancel"))
        self.dp.message.register(self.add_sudo_cmd, Command("addsudo"))
        self.dp.message.register(self.remove_sudo_cmd, Command("rmsudo"))
        self.dp.message.register(self.set_rate_cmd, Command("setrate"))
        self.dp.message.register(self.handle_file, F.document.file_name.endswith(".txt"))
        self.dp.message.register(self.handle_ports, F.text)
        self.dp.callback_query.register(self.handle_rate_callback, F.data.startswith("rate_"))

    async def is_allowed(self, user_id: int) -> bool:
        return user_id == Config.OWNER_ID or user_id in self.sudo_users

    def get_user_state(self, user_id: int) -> UserState:
        if user_id not in self.user_states:
            self.user_states[user_id] = UserState()
        return self.user_states[user_id]

    async def start_cmd(self, message: types.Message):
        if not await self.is_allowed(message.from_user.id):
            await message.reply("You are not authorized to use this bot.")
            return
        
        welcome_text = (
            "Welcome to the Port Scanner Bot!\n\n"
            "Commands:\n"
            "/start - Show this message\n"
            "/help - Show detailed help\n"
            "/status - Check current scan status\n"
            "/cancel - Cancel ongoing scan\n"
            "/setrate - Set scan rate\n"
            "/addsudo - Add sudo user (owner only)\n"
            "/rmsudo - Remove sudo user (owner only)\n\n"
            "To begin, upload a .txt file with IP ranges."
        )
        await message.reply(welcome_text)

    async def help_cmd(self, message: types.Message):
        if not await self.is_allowed(message.from_user.id):
            return
        
        help_text = (
            "Detailed Help:\n\n"
            "1. Upload a .txt file with IP ranges (one per line) in any of these formats:\n"
            "   - CIDR notation: 12.0.0.0/8\n"
            "   - IP range: 12.0.0.0-16.0.0.0\n"
            "   - Single IP: 12.0.0.0\n\n"
            "2. Enter ports to scan in any of these formats:\n"
            "   - Single port: 80\n"
            "   - Multiple ports: 80,443,8080\n"
            "   - Port range: 80-100\n"
            "   - Combined: 80,443,1000-2000\n\n"
            "Scan Rates:\n"
            "Slow: 1,000 packets/sec\n"
            "Normal: 10,000 packets/sec\n"
            "Fast: 100,000 packets/sec\n\n"
            "File size limit: 10MB\n"
            "Scan timeout: 10 hour"
        )
        await message.reply(help_text)

    async def status_cmd(self, message: types.Message):
        if not await self.is_allowed(message.from_user.id):
            return
        
        state = self.get_user_state(message.from_user.id)
        status = (
            "Current Status:\n"
            f"Active scans: {state.active_scans}\n"
            f"Current scan rate: {state.scan_rate}\n"
            f"Ports: {', '.join(map(str, sorted(state.ports))) if state.ports else 'Not set'}\n"
            f"Sudo users: {', '.join(map(str, self.sudo_users))}"
        )
        await message.reply(status)

    async def add_sudo_cmd(self, message: types.Message):
        if message.from_user.id != Config.OWNER_ID:
            await message.reply("Only the owner can add sudo users.")
            return

        try:
            new_sudo_id = int(message.text.split()[1])
            if new_sudo_id in self.sudo_users:
                await message.reply("User is already a sudo user.")
                return
            
            self.sudo_users.append(new_sudo_id)
            await message.reply(f"User {new_sudo_id} added as sudo user.")
        except (IndexError, ValueError):
            await message.reply("Usage: /addsudo {user_id}")

    async def remove_sudo_cmd(self, message: types.Message):
        if message.from_user.id != Config.OWNER_ID:
            await message.reply("Only the owner can remove sudo users.")
            return

        try:
            sudo_id = int(message.text.split()[1])
            if sudo_id == Config.OWNER_ID:
                await message.reply("Cannot remove the owner from sudo users.")
                return
            
            if sudo_id not in self.sudo_users:
                await message.reply("User is not a sudo user.")
                return
            
            self.sudo_users.remove(sudo_id)
            await message.reply(f"User {sudo_id} removed from sudo users.")
        except (IndexError, ValueError):
            await message.reply("Usage: /rmsudo {user_id}")

    async def set_rate_cmd(self, message: types.Message):
        if not await self.is_allowed(message.from_user.id):
            return
        
        markup = InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text="Slow", callback_data="rate_slow"),
                InlineKeyboardButton(text="Normal", callback_data="rate_normal"),
                InlineKeyboardButton(text="Fast", callback_data="rate_fast")
            ]
        ])
        await message.reply("Select scan rate:", reply_markup=markup)

    async def handle_rate_callback(self, callback_query: types.CallbackQuery):
        user_id = callback_query.from_user.id
        if not await self.is_allowed(user_id):
            return
        
        rate = callback_query.data.split("_")[1]
        state = self.get_user_state(user_id)
        state.scan_rate = rate
        await callback_query.message.edit_text(f"Scan rate set to: {rate}")

    async def handle_file(self, message: types.Message):
        user_id = message.from_user.id
        if not await self.is_allowed(user_id):
            await message.reply("You are not authorized to use this bot.")
            return

        if message.document.file_size > Config.MAX_FILE_SIZE:
            await message.reply("File too large. Maximum size: 1MB")
            return

        state = self.get_user_state(user_id)
        await self.cleanup_files(state)

        try:
            os.makedirs("files", exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            file_path = f"files/{user_id}_{timestamp}_ranges.txt"
            await self.bot.download(
                message.document,
                destination=file_path
            )
            
            state.file_path = file_path
            state.result_file = file_path.replace("ranges.txt", "results.txt")
            
            with open(file_path, 'r') as f:
                lines = f.readlines()
                if not lines:
                    await message.reply("File is empty. Please upload a file with IP ranges.")
                    await self.cleanup_files(state)
                    return
                
                for line in lines:
                    line = line.strip()
                    if not line or not is_valid_ip_range(line):
                        await message.reply(
                            "Invalid IP range format detected. Please ensure each line contains either:\n"
                            "- CIDR notation (e.g., 12.0.0.0/8)\n"
                            "- IP range (e.g., 12.0.0.0-16.0.0.0)\n"
                            "- Single IP (e.g., 12.0.0.0)"
                        )
                        await self.cleanup_files(state)
                        return

            await message.reply(
                "File uploaded and validated successfully!\n"
                "Now send the ports to scan in any of these formats:\n"
                "- Single port: 80\n"
                "- Multiple ports: 80,443,8080\n"
                "- Port range: 80-100\n"
                "- Combined: 80,443,1000-2000"
            )

        except Exception as e:
            logger.error(f"Error handling file upload: {e}")
            await message.reply("Error processing file. Please try again.")
            await self.cleanup_files(state)

    async def handle_ports(self, message: types.Message):
        user_id = message.from_user.id
        if not await self.is_allowed(user_id):
            return

        state = self.get_user_state(user_id)
        if not state.file_path:
            return  # Ignore text messages if no file is uploaded

        try:
            ports = set()
            for part in message.text.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    if not (1 <= start <= 65535 and 1 <= end <= 65535):
                        raise ValueError
                    ports.update(range(start, end + 1))
                else:
                    port = int(part)
                    if not 1 <= port <= 65535:
                        raise ValueError
                    ports.add(port)
        except ValueError:
            await message.reply(
                "Invalid port format. Examples:\n"
                "Single port: 80\n"
                "Multiple ports: 80,443,8080\n"
                "Port range: 80-100"
            )
            return

        if state.active_scans >= Config.MAX_CONCURRENT_SCANS:
            await message.reply("Maximum concurrent scans reached. Please wait.")
            return

        state.ports = ports
        state.active_scans += 1
        
        await message.reply(
            f"Starting scan on ports {', '.join(map(str, sorted(ports)))}\n"
            f"Rate: {state.scan_rate} ({Config.SCAN_RATES[state.scan_rate]} packets/sec)\n"
            "Type /cancel to stop."
        )
        
        asyncio.create_task(self.run_scan(message, user_id))

    async def run_scan(self, message: types.Message, user_id: int):
        state = self.get_user_state(user_id)
        scan_start_time = datetime.now()
        progress_msg = await message.reply("Initializing scan...")
        last_text = [""]
        scanned_count = 0
        found_ips = []

        try:
            with open(state.file_path, "r") as file:
                ip_ranges = file.read().splitlines()

            ports_str = ','.join(map(str, state.ports))

            for ip_range in ip_ranges:
                if state.cancel:
                    for process in state.current_processes:
                        try:
                            process.kill()
                            await process.wait()
                        except:
                            pass
                    await self.safe_edit_text(progress_msg, "Scan cancelled. Sending partial results...", last_text)

                    if found_ips:
                        await message.reply_document(
                            FSInputFile(state.result_file, filename=f"partial_scan_results.txt"),
                            caption=f"Scan cancelled.\nFound {len(found_ips)} open ports so far."
                        )
                    else:
                        await message.reply("Scan cancelled. No results to display.")
                    break

                if (datetime.now() - scan_start_time).total_seconds() > Config.SCAN_TIMEOUT:
                    await self.safe_edit_text(progress_msg, "Scan timeout reached. Stopping...", last_text)
                    break

                cmd = f"sudo masscan -p{ports_str} --rate={Config.SCAN_RATES[state.scan_rate]} {ip_range}"
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                state.current_processes.append(process)

                while True:
                    if state.cancel:
                        break
                    
                    line = await process.stdout.readline()
                    if not line:
                        break
                    
                    line = line.decode().strip()
                    if "Discovered open port" in line:
                        parts = line.split()
                        ip = parts[5]
                        port = parts[3].split('/')[0]
                        result = f"{ip}:{port}"
                        found_ips.append(result)
                        with open(state.result_file, "a") as f:
                            f.write(f"{result}\n")

                    scanned_count += 1
                    if scanned_count % 10 == 0:
                        elapsed = (datetime.now() - scan_start_time).seconds
                        hours, remainder = divmod(elapsed, 3600)
                        minutes, seconds = divmod(remainder, 60)
                        formatted_time = f"{int(hours)}:{int(minutes):02}:{int(seconds):02}"
                        progress_text = (
                            f"Scan in progress\n"
                            f"Time elapsed: {formatted_time}\n"
                            f"IPs found: {len(found_ips)}\n"
                            f"Current range: {ip_range}\n"
                            f"Ports: {ports_str}\n"
                            f"Type /cancel to stop"
                        )
                        await self.safe_edit_text(progress_msg, progress_text, last_text)

                state.current_processes.remove(process)
                await process.wait()

            if found_ips and not state.cancel:
                await message.reply_document(
                    FSInputFile(state.result_file, filename=f"scan_results.txt"),
                    caption=f"Scan complete\nFound {len(found_ips)} open ports"
                )
            elif not state.cancel:
                await self.safe_edit_text(progress_msg, "Scan complete\nNo open ports found", last_text)

        except Exception as e:
            logger.error(f"Scan error: {e}")
            await self.safe_edit_text(progress_msg, f"Error during scan: {str(e)}", last_text)

        finally:
            state.active_scans -= 1
            state.current_processes.clear()
            await self.cleanup_files(state)
            if state.cancel:
                state.cancel = False

    async def cancel_cmd(self, message: types.Message):
        user_id = message.from_user.id
        if not await self.is_allowed(user_id):
            return

        state = self.get_user_state(user_id)
        if state.active_scans == 0:
            await message.reply("No active scans to cancel.")
            return

        state.cancel = True
        for process in state.current_processes:
            try:
                process.kill()
            except:
                pass
        await message.reply("Canceling scan...")

    async def add_sudo_cmd(self, message: types.Message):
        if message.from_user.id != Config.OWNER_ID:
            await message.reply("Only the owner can add sudo users.")
            return

        try:
            new_sudo_id = int(message.text.split()[1])
            if new_sudo_id in self.sudo_users:
                await message.reply("User is already a sudo user.")
                return
            
            self.sudo_users.append(new_sudo_id)
            await message.reply(f"User {new_sudo_id} added as sudo user.")
        except (IndexError, ValueError):
            await message.reply("Usage: /addsudo {user_id}")

    async def remove_sudo_cmd(self, message: types.Message):
        if message.from_user.id != Config.OWNER_ID:
            await message.reply("Only the owner can remove sudo users.")
            return

        try:
            sudo_id = int(message.text.split()[1])
            if sudo_id == Config.OWNER_ID:
                await message.reply("Cannot remove the owner from sudo users.")
                return
            
            if sudo_id not in self.sudo_users:
                await message.reply("User is not a sudo user.")
                return
            
            self.sudo_users.remove(sudo_id)
            await message.reply(f"User {sudo_id} removed from sudo users.")
        except (IndexError, ValueError):
            await message.reply("Usage: /rmsudo {user_id}")

    @staticmethod
    async def safe_edit_text(message: types.Message, new_text: str, last_text: List[str]):
        try:
            if new_text != last_text[0]:
                await message.edit_text(new_text)
                last_text[0] = new_text
        except TelegramAPIError as e:
            logger.warning(f"Failed to edit message: {e}")

    @staticmethod
    async def cleanup_files(state: UserState):
        for file_path in [state.file_path, state.result_file]:
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception as e:
                    logger.error(f"Failed to cleanup file {file_path}: {e}")

    async def start(self):
        logger.info("Starting bot...")
        await self.dp.start_polling(self.bot)

async def main():
    bot = ScannerBot()
    await bot.start()

if __name__ == "__main__":
    asyncio.run(main())