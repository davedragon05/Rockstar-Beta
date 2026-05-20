from django.shortcuts import render, redirect, get_object_or_404
from App.users.models import Staff, Role, StaffHistory, Position, Department
from App.users.forms import StaffForm
from App.authentication.decorators import login_required
from App.authentication.views import get_current_employee
from App.authentication.models import LoginHistory, UserAccount
from django.db.models import F, Q, Case, When, Value, BooleanField
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from datetime import datetime, date, timedelta
from django.http import HttpResponseForbidden, JsonResponse

@login_required
def master_dashboard(request):
    emp = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)

    role_url_map = {
        "Sales": "sales:sales_dashboard",
        "Human Resource": "human_resource:hr_dashboard",
    }

    roles = Role.objects.exclude(role_name__in=["Master", "Developer"])

    departments = []
    for role in roles:
        url_name = role_url_map.get(role.role_name)
        if url_name:
            user_count = Staff.objects.filter(role_id=role.id).count()
            description = getattr(role, "description", "")
            departments.append({
                "name": role.role_name,
                "url": url_name,
                "user_count": user_count,
                "description": description
            })

    context = {
        "employee": emp,
        "departments": departments,
        "is_owner": is_owner,
    }

    # ── Keep session department in sync ──────────────────────────────────────
    # When a Developer or Master lands on the master dashboard via direct URL
    # (not via the select_department POST), current_dept may be stale or absent.
    # Force it to "All" here so the navbar badge and department switcher
    # always reflect reality.
    if not is_owner:
        emp_num = request.session.get('employee_number')
        if emp_num and emp:
            role_name = emp.role.role_name if emp.role else ''
            if role_name in ('Master', 'Developer'):
                request.session['current_dept'] = 'All'
                request.session.modified = True
    else:
        request.session['current_dept'] = 'All'
        request.session.modified = True

    return render(request, "master/master_dashboard.html", context)


# ============================================
# LOGIN HISTORY / AUDIT TRAIL
# ============================================
@login_required
def login_history(request):
    emp = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    
    emp_num = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        allowed_roles = ['Owner', 'Master', 'Developer', 'Admin']
        if role_name not in allowed_roles and not is_owner:
            from django.contrib import messages
            messages.error(request, "You don't have permission to view login history.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        from django.contrib import messages
        messages.error(request, "You don't have permission to view login history.")
        return redirect('master_dashboard:master_dashboard')
    
    search = request.GET.get('search', '')
    status_filter = request.GET.get('status', '')
    start_date = request.GET.get('start_date', '')
    end_date = request.GET.get('end_date', '')
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return ajax_login_history(request, search, status_filter, start_date, end_date)
    
    history = LoginHistory.objects.select_related('employee').order_by('-login_time')
    
    if search:
        history = history.filter(
            Q(employee_number__icontains=search) | 
            Q(ip_address__icontains=search)
        )
    
    if status_filter:
        history = history.filter(status=status_filter)
    
    if start_date:
        try:
            start = datetime.strptime(start_date, '%Y-%m-%d').date()
            history = history.filter(login_time__date__gte=start)
        except ValueError:
            pass
    
    if end_date:
        try:
            end = datetime.strptime(end_date, '%Y-%m-%d').date()
            history = history.filter(login_time__date__lte=end)
        except ValueError:
            pass
    
    total_logins = LoginHistory.objects.filter(status='success').count()
    total_failed = LoginHistory.objects.filter(status='failed').count()
    unique_users = LoginHistory.objects.exclude(employee_number='').values('employee_number').distinct().count()
    
    paginator = Paginator(history, 25)
    page_number = request.GET.get('page', 1)
    
    try:
        page_obj = paginator.page(page_number)
    except PageNotAnInteger:
        page_obj = paginator.page(1)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)
    
    return render(request, 'master/login_history.html', {
        'page_obj': page_obj,
        'total_logins': total_logins,
        'total_failed': total_failed,
        'unique_users': unique_users,
        'search': search,
        'status_filter': status_filter,
        'start_date': start_date,
        'end_date': end_date,
    })


# ============================================
# AJAX LOGIN HISTORY
# ============================================
def ajax_login_history(request, search='', status_filter='', start_date='', end_date=''):
    from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
    from django.utils.dateformat import DateFormat
    
    history = LoginHistory.objects.select_related('employee').order_by('-login_time')
    
    if search:
        history = history.filter(
            Q(employee_number__icontains=search) | 
            Q(ip_address__icontains=search)
        )
    
    if status_filter:
        history = history.filter(status=status_filter)
    
    if start_date:
        try:
            start = datetime.strptime(start_date, '%Y-%m-%d').date()
            history = history.filter(login_time__date__gte=start)
        except ValueError:
            pass
    
    if end_date:
        try:
            end = datetime.strptime(end_date, '%Y-%m-%d').date()
            history = history.filter(login_time__date__lte=end)
        except ValueError:
            pass
    
    paginator = Paginator(history, 25)
    page_number = request.GET.get('page', 1)
    
    try:
        page_obj = paginator.page(page_number)
    except PageNotAnInteger:
        page_obj = paginator.page(1)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)
    
    logs = []
    for log in page_obj:
        logs.append({
            'login_time': log.login_time.strftime('%b %d, %Y %H:%M:%S') if log.login_time else '-',
            'employee_number': log.employee_number or '-',
            'status': log.status,
            'ip_address': log.ip_address or '-',
            'device_type': log.get_device_type(),
            'browser': log.get_browser_name(),
            'os': log.get_os_name(),
            'location': log.get_location(),
            'failure_reason': log.failure_reason or '-',
            'user_agent': log.user_agent or '',
        })
    
    return JsonResponse({
        'logs': logs,
        'has_next': page_obj.has_next(),
        'has_previous': page_obj.has_previous(),
        'current_page': page_obj.number,
        'num_pages': page_obj.paginator.num_pages,
        'search': search,
        'status_filter': status_filter,
        'start_date': start_date,
        'end_date': end_date,
    })


# ============================================
# STAFF HISTORY - MASTER DASHBOARD
# ============================================
@login_required
def staff_history_master_list(request):
    emp = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    
    emp_num = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        allowed_roles = ['Owner', 'Master', 'Developer', 'Admin']
        if role_name not in allowed_roles and not is_owner:
            from django.contrib import messages
            messages.error(request, "You don't have permission to view staff history.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        from django.contrib import messages
        messages.error(request, "You don't have permission to view staff history.")
        return redirect('master_dashboard:master_dashboard')
    
    history_records = StaffHistory.objects.select_related('staff', 'changed_by').all()
    
    staff_id = request.GET.get('staff')
    field_name = request.GET.get('field')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    if staff_id:
        history_records = history_records.filter(staff_id=staff_id)
    
    if field_name:
        history_records = history_records.filter(field_name=field_name)
    
    if start_date:
        try:
            start = datetime.strptime(start_date, '%Y-%m-%d').date()
            history_records = history_records.filter(changed_at__date__gte=start)
        except ValueError:
            pass
    
    if end_date:
        try:
            end = datetime.strptime(end_date, '%Y-%m-%d').date()
            history_records = history_records.filter(changed_at__date__lte=end)
        except ValueError:
            pass
    
    history_records = history_records.order_by('-changed_at')
    
    paginator = Paginator(history_records, 20)
    page_number = request.GET.get('page', 1)
    history_page = paginator.get_page(page_number)
    
    staff_list = Staff.objects.all().order_by('last_name', 'first_name')
    field_choices = StaffHistory.FIELD_CHOICES
    
    context = {
        "employee": emp,
        "is_owner": is_owner,
        'history_records': history_page,
        'staff_list': staff_list,
        'field_choices': field_choices,
        'staff_id': staff_id,
        'field_name': field_name,
        'start_date': start_date,
        'end_date': end_date,
    }

    return render(request, "master/staff_history_list.html", context)


# ============================================
# USER MANAGEMENT - MASTER DASHBOARD
# ============================================

@login_required
def master_user_list(request):
    emp = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    
    emp_num = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        allowed_roles = ['Owner', 'Master', 'Developer', 'Admin']
        if role_name not in allowed_roles and not is_owner:
            from django.contrib import messages
            messages.error(request, "You don't have permission to view user management.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        from django.contrib import messages
        messages.error(request, "You don't have permission to view user management.")
        return redirect('master_dashboard:master_dashboard')
    
    staff_list = Staff.objects.select_related('role', 'departmentlink', 'positionlink').all().order_by('last_name', 'first_name')
    roles = Role.objects.filter(is_active=True)
    departments = Department.objects.filter(is_active=True)
    
    context = {
        "employee": emp,
        "is_owner": is_owner,
        'staff_list': staff_list,
        'roles': roles,
        'departments': departments,
    }

    return render(request, "master/user_list.html", context)


@login_required
def master_user_add(request):
    emp = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    
    emp_num = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        allowed_roles = ['Owner', 'Master', 'Developer', 'Admin']
        if role_name not in allowed_roles and not is_owner:
            from django.contrib import messages
            messages.error(request, "You don't have permission to add users.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        from django.contrib import messages
        messages.error(request, "You don't have permission to add users.")
        return redirect('master_dashboard:master_dashboard')
    
    if request.method == 'POST':
        form = StaffForm(request.POST)
        if form.is_valid():
            staff = form.save(commit=False)
            employee_id = request.session.get('employee_id')
            if employee_id:
                try:
                    staff._changed_by = Staff.objects.get(pk=employee_id)
                except Staff.DoesNotExist:
                    pass
            staff.save()
            from django.contrib import messages
            messages.success(request, "Employee added successfully!")
            return redirect('master_dashboard:master_user_list')
    else:
        form = StaffForm()
    
    context = {
        "employee": emp,
        "is_owner": is_owner,
        'form': form,
        'action': 'Add',
    }

    return render(request, "master/user_form.html", context)


@login_required
def master_user_edit(request, pk):
    emp = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    
    emp_num = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        allowed_roles = ['Owner', 'Master', 'Developer', 'Admin']
        if role_name not in allowed_roles and not is_owner:
            from django.contrib import messages
            messages.error(request, "You don't have permission to edit users.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        from django.contrib import messages
        messages.error(request, "You don't have permission to edit users.")
        return redirect('master_dashboard:master_dashboard')
    
    staff = get_object_or_404(Staff, pk=pk)
    
    if request.method == 'POST':
        form = StaffForm(request.POST, instance=staff)
        if form.is_valid():
            original_employee_number = staff.employee_number
            staff = form.save(commit=False)
            if not staff.employee_number:
                staff.employee_number = original_employee_number
            employee_id = request.session.get('employee_id')
            if employee_id:
                try:
                    staff._changed_by = Staff.objects.get(pk=employee_id)
                except Staff.DoesNotExist:
                    pass
            staff.save()
            from django.contrib import messages
            messages.success(request, "Employee updated successfully!")
            return redirect('master_dashboard:master_user_list')
    else:
        form = StaffForm(instance=staff)
    
    context = {
        "employee": emp,
        "is_owner": is_owner,
        'form': form,
        'action': 'Edit',
        'staff': staff,
    }

    return render(request, "master/user_form.html", context)


@login_required
def master_user_detail(request, pk):
    emp = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    
    emp_num = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        allowed_roles = ['Owner', 'Master', 'Developer', 'Admin']
        if role_name not in allowed_roles and not is_owner:
            from django.contrib import messages
            messages.error(request, "You don't have permission to view user details.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        from django.contrib import messages
        messages.error(request, "You don't have permission to view user details.")
        return redirect('master_dashboard:master_dashboard')
    
    staff = get_object_or_404(Staff, pk=pk)
    
    context = {
        "employee": emp,
        "is_owner": is_owner,
        'staff': staff,
    }

    return render(request, "master/user_detail.html", context)


@login_required
def master_user_delete(request, pk):
    emp = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    
    emp_num = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        allowed_roles = ['Owner', 'Master', 'Developer', 'Admin']
        if role_name not in allowed_roles and not is_owner:
            from django.contrib import messages
            messages.error(request, "You don't have permission to delete users.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        from django.contrib import messages
        messages.error(request, "You don't have permission to delete users.")
        return redirect('master_dashboard:master_dashboard')
    
    staff = get_object_or_404(Staff, pk=pk)
    
    if request.method == 'POST':
        staff.delete()
        from django.contrib import messages
        messages.success(request, "Employee deleted successfully!")
        return redirect('master_dashboard:master_user_list')
    
    return render(request, "master/user_detail.html", {
        "employee": emp,
        "is_owner": is_owner,
        'staff': staff,
    })


@login_required
def master_update_staff_role(request):
    if request.method == 'POST':
        staff_id = request.POST.get("staff_id")
        role_id = request.POST.get("role")
        staff = get_object_or_404(Staff, id=staff_id)
        staff.role_id = role_id if role_id else None
        staff.save()
        from django.contrib import messages
        messages.success(request, f"Role updated for {staff.first_name} {staff.last_name}")
    return redirect('master_dashboard:master_user_list')


# ============================================
# ATTENDANCE CLOCK - MASTER DASHBOARD
# ============================================
@login_required
def attendance_clock_master(request):
    from django.utils import timezone
    from django.contrib import messages
    from App.users.models import Staff
    from App.human_resource.models import Attendance, EmployeeShiftRule, LeaveCredit

    emp_num  = request.session.get('employee_number')
    is_owner = request.session.get('is_owner', False)

    if not emp_num:
        return redirect('login')

    if is_owner:
        messages.error(request, "Owners cannot clock in/out. Please use department dashboards.")
        return redirect('master_dashboard:master_dashboard')

    try:
        employee = Staff.objects.get(employee_number=emp_num)
    except Staff.DoesNotExist:
        messages.error(request, "Employee not found.")
        return redirect('master_dashboard:master_dashboard')

    today      = date.today()
    now_local  = timezone.localtime()
    now_time   = now_local.time()
    is_weekend = today.weekday() >= 5

    shift_rule = EmployeeShiftRule.objects.filter(
        shift=employee.shift, rank=employee.rank
    ).first()

    # ── Determine correct shift date ──────────────────────────────────────────
    # Night shifts cross midnight: identified by clock_out < clock_in_start.
    # Roll back to yesterday only when we are in the early-morning tail of the
    # previous night's shift (i.e. now_time <= clock_out AND crosses midnight).
    shift_date = today

    if shift_rule and shift_rule.clock_in_start and shift_rule.clock_out:
        crosses_midnight = shift_rule.clock_out < shift_rule.clock_in_start
        if crosses_midnight and now_time <= shift_rule.clock_out:
            shift_date = today - timedelta(days=1)

    # ── Clock-in window guard ─────────────────────────────────────────────────
    # Clock-in is allowed from clock_in_start until shift ends.
    clock_in_allowed = True  # default: allow when no shift rule
    if shift_rule and shift_rule.clock_in_start and shift_rule.clock_out:
        crosses_midnight = shift_rule.clock_out < shift_rule.clock_in_start
        if crosses_midnight:
            # Valid window: clock_in_start → 23:59 → 00:00 → clock_out
            clock_in_allowed = (
                now_time >= shift_rule.clock_in_start or
                now_time <= shift_rule.clock_out
            )
        else:
            clock_in_allowed = shift_rule.clock_in_start <= now_time <= shift_rule.clock_out

    shift_rule_incomplete = False
    no_shift_rule         = False
    if shift_rule:
        if not all([shift_rule.clock_in_start, shift_rule.clock_out]):
            shift_rule_incomplete = True
    else:
        no_shift_rule = True
        messages.warning(
            request,
            "No shift rule configured for your position. "
            "Please contact HR to configure your schedule."
        )

    # ── Fetch attendance for the correct shift date ───────────────────────────
    attendance = Attendance.objects.filter(employee=employee, date=shift_date).first()
    
    # ── Fallback: If no attendance found for shift_date, check if user already completed 
    # a shift today (clock_in AND clock_out exist). If not, look for any open attendance ─
    if not attendance:
        # First check: is there any attendance today where user already completed their shift?
        completed_today = Attendance.objects.filter(
            employee=employee,
            clock_in__isnull=False,
            clock_out__isnull=False,
            date=today
        ).first()
        
        if not completed_today:
            # No completed shift today, look for any open attendance (clocked in but not out)
            open_attendance = Attendance.objects.filter(
                employee=employee,
                clock_in__isnull=False,
                clock_out__isnull=True
            ).order_by('-date').first()
            
            if open_attendance:
                attendance = open_attendance
                shift_date = attendance.date  # Update shift_date to match the found record

    # ── Check for an unresolved failed-to-clock-out from a previous shift ─────
    if not attendance:
        prev_open = Attendance.objects.filter(
            employee=employee,
            clock_in__isnull=False,
            clock_out__isnull=True,
        ).order_by('-date').first()

        if prev_open and shift_rule and shift_rule.clock_out:
            grace_minutes = getattr(shift_rule, 'clock_out_grace_period', 60)

            if prev_open.clock_in and prev_open.clock_in > shift_rule.clock_out:
                # Night shift: clock_out is on the day after the attendance date
                clock_out_date = prev_open.date + timedelta(days=1)
            else:
                clock_out_date = prev_open.date

            clock_out_dt  = datetime.combine(clock_out_date, shift_rule.clock_out)
            grace_end_dt  = clock_out_dt + timedelta(minutes=grace_minutes)
            current_dt    = datetime.combine(today, now_time)

            if current_dt > grace_end_dt:
                is_acknowledged = prev_open.note and prev_open.note.startswith('[Acknowledged]')
                if not is_acknowledged:
                    prev_open.status = 'failed_to_clock_out'
                    prev_open.save()
                    messages.warning(
                        request,
                        f"You forgot to clock out on {prev_open.date}. "
                        "Status updated to 'Failed to Clock Out'."
                    )

    # ── Auto-absent marking ───────────────────────────────────────────────────
    shift_absent_record = Attendance.objects.filter(
        employee=employee,
        date=shift_date,
        status='absent',
    ).first()

    if (
        not shift_absent_record
        and not attendance
        and shift_rule
        and shift_rule.clock_out
        and not is_weekend
    ):
        grace_period_minutes = getattr(shift_rule, 'absent_grace_period', 60)

        if shift_rule.clock_in_start and shift_rule.clock_out:
            if shift_rule.clock_in_start > shift_rule.clock_out:
                # Night shift: clock_out is on the next calendar day
                clock_out_date = shift_date + timedelta(days=1)
            else:
                clock_out_date = shift_date
        else:
            clock_out_date = shift_date

        clock_out_dt       = datetime.combine(clock_out_date, shift_rule.clock_out)
        absent_deadline_dt = clock_out_dt + timedelta(minutes=grace_period_minutes)
        current_dt         = datetime.combine(today, now_time)

        if current_dt > absent_deadline_dt:
            from App.human_resource.models import LeaveRequest
            on_leave = LeaveRequest.objects.filter(
                employee=employee,
                status='approved',
                start_date__lte=shift_date,
                end_date__gte=shift_date,
            ).exists()

            if not on_leave:
                Attendance.objects.create(
                    employee=employee,
                    date=shift_date,
                    status='absent',
                    note='Auto-marked: No clock in after shift end + grace period',
                )
                shift_absent_record = Attendance.objects.filter(
                    employee=employee,
                    date=shift_date,
                    status='absent',
                ).first()

    # ── Auto-flag failed_to_clock_out if shift has ended ─────────────────────
    # Only apply to records from PREVIOUS days, not today's active attendance
    if attendance and attendance.clock_in and not attendance.clock_out:
        if shift_rule and shift_rule.clock_out:
            # Only flag as failed_to_clock_out if this is NOT today's attendance
            if attendance.date and attendance.date != today:
                # Calculate deadline using grace period (clock_out + grace_period)
                grace_period = getattr(shift_rule, 'clock_out_grace_period', 60)  # Default 60 minutes
                clock_out_dt = datetime.combine(attendance.date, shift_rule.clock_out)
                deadline_dt = clock_out_dt + timedelta(minutes=grace_period)
                deadline_time = deadline_dt.time()
                
                if now_time > deadline_time:
                    attendance.add_status('failed_to_clock_out')
                    if 'failed_to_clock_out' not in (attendance.status or ''):
                        attendance.status = 'failed_to_clock_out'
                    attendance.save()

    # ── HTMX/AJAX Support Helpers ──────────────────────────────────────────────────
    def _is_ajax():
        return request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    def _is_htmx():
        return request.headers.get('HX-Request') == 'true'

    def _recalculate_attendance_status(attendance, shift_rule):
        """Recalculate attendance status including late, early_leave, missing_lunch, overlunch"""
        from datetime import datetime, timedelta, date
        from django.utils import timezone
        
        statuses_list = []
        now_local = timezone.localtime()
        now_time = now_local.time()
        
        if attendance.clock_in:
            if shift_rule.clock_in_start and attendance.clock_in > shift_rule.clock_in_start:
                attendance.status = 'late'
                statuses_list.append('late')
                clock_in_start_dt = datetime.combine(attendance.date, shift_rule.clock_in_start)
                clock_in_dt = datetime.combine(attendance.date, attendance.clock_in)
                attendance.late_minutes = int(
                    (clock_in_dt - clock_in_start_dt).total_seconds() / 60
                )
            else:
                attendance.status = 'present'
                statuses_list.append('present')
                attendance.late_minutes = 0
        else:
            attendance.status = 'absent'
            statuses_list.append('absent')
            attendance.late_minutes = 0
        
        if attendance.overlunch_minutes > 0 and not attendance.overlunch_validated:
            attendance.deduction_minutes = attendance.late_minutes + attendance.overlunch_minutes
        else:
            attendance.deduction_minutes = attendance.late_minutes
        
        if getattr(shift_rule, 'lunch_required', False):
            # Missing Lunch: lunch required but user never started lunch
            if not attendance.lunch_in:
                if 'missing_lunch' not in statuses_list:
                    statuses_list.append('missing_lunch')
            # Overlunch: has lunch_in but no lunch_out (still on lunch break when clocking out)
            elif attendance.lunch_in and not attendance.lunch_out:
                if 'overlunch_pending' not in statuses_list:
                    statuses_list.append('overlunch_pending')
        
        # Check for early_leave - clock_out BEFORE scheduled clock_out time
        # Handle night shifts where clock_out is on the next day
        if attendance.clock_out and shift_rule and shift_rule.clock_out and shift_rule.clock_in_start:
            # Check if this is a night shift (clock_out < clock_in_start means crosses midnight)
            is_night_shift = shift_rule.clock_out < shift_rule.clock_in_start
            
            # Calculate actual shift duration in hours
            if is_night_shift:
                # Night shift: e.g., 21:00 to 05:00 = 8 hours
                shift_hours = (datetime.combine(date.today(), shift_rule.clock_out) - datetime.combine(date.today(), shift_rule.clock_in_start)).total_seconds() / 3600
                if shift_hours < 0:
                    # Crosses midnight, add 24 hours
                    shift_hours += 24
            else:
                # Regular day shift
                shift_hours = (datetime.combine(date.today(), shift_rule.clock_out) - datetime.combine(date.today(), shift_rule.clock_in_start)).total_seconds() / 3600
            
            # Calculate actual time worked in hours
            if attendance.clock_in:
                if attendance.clock_out < attendance.clock_in:
                    # Crosses midnight
                    time_worked_hours = (datetime.combine(date.today(), attendance.clock_out) + timedelta(days=1) - datetime.combine(date.today(), attendance.clock_in)).total_seconds() / 3600
                else:
                    time_worked_hours = (datetime.combine(date.today(), attendance.clock_out) - datetime.combine(date.today(), attendance.clock_in)).total_seconds() / 3600
            else:
                time_worked_hours = 0
            
            # Early leave if worked less than scheduled shift duration
            # Allow some grace (e.g., 1 minute = 0.0167 hours)
            grace_minutes = 1
            is_early = time_worked_hours < (shift_hours - (grace_minutes / 60))
            
            if is_early:
                if 'early_leave' not in statuses_list:
                    statuses_list.append('early_leave')
                if 'early_leave' not in (attendance.status or ''):
                    attendance.status = (
                        attendance.status + ' / early_leave'
                        if attendance.status else 'early_leave'
                    )
        
        attendance.statuses = ','.join(statuses_list)
        attendance.save()
        print(f"[_recalculate_attendance_status] DONE")

    def _build_context():
        # Get date filter parameters from GET request
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        
        # Build history query with optional date filtering
        history_query = Attendance.objects.filter(employee=employee)
        if start_date:
            try:
                start = datetime.strptime(start_date, '%Y-%m-%d').date()
                history_query = history_query.filter(date__gte=start)
            except ValueError:
                pass
        if end_date:
            try:
                end = datetime.strptime(end_date, '%Y-%m-%d').date()
                history_query = history_query.filter(date__lte=end)
            except ValueError:
                pass
        # Show all matching records when filtering, otherwise show last 7
        if start_date or end_date:
            history = list(history_query.order_by('-date', '-clock_in'))
        else:
            history = history_query.order_by('-date', '-clock_in')[:7]
        current_year = today.year
        vl_credit = LeaveCredit.objects.filter(
            employee=employee, leave_type='vl', year=current_year
        ).first()
        sl_credit = LeaveCredit.objects.filter(
            employee=employee, leave_type='sl', year=current_year
        ).first()
        outdated_vl = LeaveCredit.objects.filter(
            employee=employee, leave_type='vl', year__lt=current_year
        ).filter(total__gt=0).exclude(used__gte=F('total'))
        outdated_sl = LeaveCredit.objects.filter(
            employee=employee, leave_type='sl', year__lt=current_year
        ).filter(total__gt=0).exclude(used__gte=F('total'))
        no_vl_credits = not vl_credit or vl_credit.total == 0
        no_sl_credits = not sl_credit or sl_credit.total == 0
        vl_low = vl_credit and vl_credit.remaining < 3
        sl_low = sl_credit and sl_credit.remaining < 3
        failed_to_clock_out_records = Attendance.objects.filter(
            employee=employee,
        ).filter(
            Q(status='failed_to_clock_out') | Q(statuses__icontains='failed_to_clock_out')
        ).exclude(
            note__startswith='[Acknowledged]'
        ).order_by('-date')
        selected_date_str = request.GET.get('absent_date')
        selected_absent_record = None
        if selected_date_str:
            try:
                selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
                selected_absent_record = Attendance.objects.filter(
                    employee=employee,
                    date=selected_date,
                    status='absent',
                ).first()
            except ValueError:
                pass
        return {
            'attendance': attendance,
            'employee': employee,
            'shift_rule': shift_rule,
            'history': history,
            'shift_rule_incomplete': shift_rule_incomplete,
            'no_shift_rule': no_shift_rule,
            'today': today,
            'shift_date': shift_date,
            'is_weekend': is_weekend,
            'clock_in_allowed': clock_in_allowed,
            'shift_absent_record': shift_absent_record,
            'vl_credit': vl_credit,
            'sl_credit': sl_credit,
            'outdated_vl': outdated_vl,
            'outdated_sl': outdated_sl,
            # Added missing boolean variables for template
            'has_outdated_vl': outdated_vl.exists() if outdated_vl else False,
            'has_outdated_sl': outdated_sl.exists() if outdated_sl else False,
            'vl_low': vl_low,
            'sl_low': sl_low,
            'no_vl_credits': no_vl_credits,
            'no_sl_credits': no_sl_credits,
            'current_year': current_year,
            'failed_to_clock_out_records': failed_to_clock_out_records,
            'absent_count': Attendance.objects.filter(employee=employee, status='absent').count(),
            'selected_absent_record': selected_absent_record,
            # Date filter parameters
            'start_date': start_date,
            'end_date': end_date,
        }

    # ── POST ──────────────────────────────────────────────────────────────────
    if request.method == 'POST':
        # Handle form-encoded data (from regular form and AJAX)
        action = request.POST.get('action')

        if is_weekend:
            # Return JSON for AJAX requests
            if _is_ajax():
                return JsonResponse({'success': False, 'message': 'Cannot clock in on weekend.'})
            # Return rendered template for HTMX requests
            return render(request, 'master/attendance/attendance_clock.html', _build_context())

        if action == 'clock_in':
            # Allow clock-in at any time (removed restriction for early clock-in)
            # Employees can clock in anytime before or after shift start
            
            # Check for ANY existing attendance record (not just with clock_in)
            existing = Attendance.objects.filter(
                employee=employee, date=shift_date
            ).first()
            
            if existing:
                if existing.clock_in:
                    # Already clocked in
                    msg = "You have already clocked in today."
                    if _is_ajax():
                        return JsonResponse({'success': False, 'message': msg})
                    messages.info(request, msg)
                    return render(request, 'master/attendance/attendance_clock.html', _build_context())
                else:
                    # Record exists but no clock_in (e.g., auto-absent, failed_to_clock_out) - update it
                    status        = 'present'
                    late_minutes  = 0
                    statuses_list = ['present']

                    if shift_rule and shift_rule.clock_in_start and now_time > shift_rule.clock_in_start:
                        status        = 'late'
                        statuses_list = ['late']
                        clock_in_start_dt = datetime.combine(shift_date, shift_rule.clock_in_start)
                        clock_in_dt       = datetime.combine(shift_date, now_time)
                        late_minutes      = int((clock_in_dt - clock_in_start_dt).total_seconds() / 60)

                    existing.clock_in = now_time
                    existing.status = status
                    existing.late_minutes = late_minutes
                    existing.deduction_minutes = late_minutes
                    existing.statuses = ','.join(statuses_list)
                    existing.save()
                    attendance = existing
            else:
                # No existing record - create new one
                status        = 'present'
                late_minutes  = 0
                statuses_list = ['present']

                if shift_rule and shift_rule.clock_in_start and now_time > shift_rule.clock_in_start:
                    status        = 'late'
                    statuses_list = ['late']
                    clock_in_start_dt = datetime.combine(shift_date, shift_rule.clock_in_start)
                    clock_in_dt       = datetime.combine(shift_date, now_time)
                    late_minutes      = int((clock_in_dt - clock_in_start_dt).total_seconds() / 60)

                try:
                    attendance = Attendance.objects.create(
                        employee=employee,
                        date=shift_date,
                        clock_in=now_time,
                        status=status,
                        late_minutes=late_minutes,
                        deduction_minutes=late_minutes,
                        statuses=','.join(statuses_list),
                    )
                except Exception as e:
                    if _is_ajax():
                        return JsonResponse({'success': False, 'message': f'Error: {str(e)}'})
                    messages.error(request, f'Error saving attendance: {str(e)}')
                    return render(request, 'master/attendance/attendance_clock.html', _build_context())
            
            success_msg = 'You have clocked in successfully!'
            messages.success(request, success_msg)
            
            # Return JSON for AJAX requests so frontend can show proper message
            if _is_ajax():
                return JsonResponse({'success': True, 'message': success_msg})
            
            # Return rendered template for HTMX requests (HTMX expects HTML to swap into DOM)
            return render(request, 'master/attendance/attendance_clock.html', _build_context())

        elif action == 'clock_out':
            if not attendance:
                msg = "You have not clocked in yet. Please clock in first."
                if _is_ajax():
                    return JsonResponse({'success': False, 'message': msg})
                messages.error(request, msg)
                return render(request, 'master/attendance/attendance_clock.html', _build_context())
            else:
                attendance.clock_out = now_time

                if attendance.clock_in:
                    attendance_date    = attendance.date
                    clock_in_datetime  = datetime.combine(attendance_date, attendance.clock_in)
                    clock_out_datetime = datetime.combine(attendance_date, now_time)

                    # Cross-midnight: if clock_out time < clock_in time, shift crossed midnight
                    if now_time < attendance.clock_in:
                        clock_out_datetime += timedelta(days=1)

                    lunch_duration_minutes = 0
                    if attendance.lunch_in and attendance.lunch_out:
                        lunch_in_dt  = datetime.combine(attendance_date, attendance.lunch_in)
                        lunch_out_dt = datetime.combine(attendance_date, attendance.lunch_out)
                        if attendance.lunch_out < attendance.lunch_in:
                            lunch_out_dt += timedelta(days=1)
                        lunch_duration_minutes = int(
                            (lunch_out_dt - lunch_in_dt).total_seconds() / 60
                        )

                    total_minutes           = int(
                        (clock_out_datetime - clock_in_datetime).total_seconds() / 60
                    )
                    work_minutes            = max(0, total_minutes - lunch_duration_minutes)
                    attendance.hours_worked = round(work_minutes / 60, 2)

                attendance.save()
                
                # Recalculate status after clock_out (including early_leave detection)
                if shift_rule:
                    _recalculate_attendance_status(attendance, shift_rule)
                
                success_msg = 'You have clocked out successfully!'
                messages.success(request, success_msg)
                if _is_ajax():
                    return JsonResponse({'success': True, 'message': success_msg})
                return render(request, 'master/attendance/attendance_clock.html', _build_context())

        elif action == 'lunch_out':
            if not attendance:
                messages.error(request, "You have not clocked in yet. Please clock in first.")
                return render(request, 'master/attendance/attendance_clock.html', _build_context())
            elif not attendance.lunch_in:
                messages.error(request, "You have not started your lunch break yet.")
                return render(request, 'master/attendance/attendance_clock.html', _build_context())
            elif attendance.lunch_out:
                messages.error(request, "You have already ended your lunch break.")
                return render(request, 'master/attendance/attendance_clock.html', _build_context())
            else:
                attendance.lunch_out = now_time
                attendance.save()
                success_msg = 'Lunch break ended!'
                messages.success(request, success_msg)
                return render(request, 'master/attendance/attendance_clock.html', _build_context())

        # ── Recalculate status after clock_out ────────────────────────────────
        if attendance and shift_rule:
            statuses_list = []

            if attendance.clock_in:
                if shift_rule.clock_in_start and attendance.clock_in > shift_rule.clock_in_start:
                    attendance.status       = 'late'
                    statuses_list.append('late')
                    clock_in_start_dt       = datetime.combine(attendance.date, shift_rule.clock_in_start)
                    clock_in_dt             = datetime.combine(attendance.date, attendance.clock_in)
                    attendance.late_minutes = int(
                        (clock_in_dt - clock_in_start_dt).total_seconds() / 60
                    )
                else:
                    attendance.status       = 'present'
                    statuses_list.append('present')
                    attendance.late_minutes = 0
            else:
                attendance.status       = 'absent'
                statuses_list.append('absent')
                attendance.late_minutes = 0

            if attendance.overlunch_minutes > 0 and not attendance.overlunch_validated:
                attendance.deduction_minutes = attendance.late_minutes + attendance.overlunch_minutes
            else:
                attendance.deduction_minutes = attendance.late_minutes

            if getattr(shift_rule, 'lunch_required', False):
                # Missing Lunch: lunch required but user never started lunch
                if not attendance.lunch_in:
                    if 'missing_lunch' not in statuses_list:
                        statuses_list.append('missing_lunch')
                # Overlunch: has lunch_in but no lunch_out (still on lunch break when clocking out)
                elif attendance.lunch_in and not attendance.lunch_out:
                    if 'overlunch_pending' not in statuses_list:
                        statuses_list.append('overlunch_pending')

            if attendance.clock_out and shift_rule.clock_out:
                if attendance.clock_out < shift_rule.clock_out:
                    if 'early_leave' not in statuses_list:
                        statuses_list.append('early_leave')
                    if 'early_leave' not in (attendance.status or ''):
                        attendance.status = (
                            attendance.status + ' / early_leave'
                            if attendance.status else 'early_leave'
                        )

            attendance.statuses = ','.join(statuses_list)
            attendance.save()

        elif attendance:
            attendance.status            = 'present' if attendance.clock_in else 'absent'
            attendance.late_minutes      = 0
            attendance.deduction_minutes = 0
            attendance.statuses          = 'present' if attendance.clock_in else 'absent'
            attendance.save()

    def _get_attendance_json(att):
        """Convert attendance object to JSON-serializable dict"""
        if not att:
            return None
        return {
            'clock_in': att.clock_in.strftime('%H:%M:%S') if att.clock_in else None,
            'clock_out': att.clock_out.strftime('%H:%M:%S') if att.clock_out else None,
            'lunch_in': att.lunch_in.strftime('%H:%M:%S') if att.lunch_in else None,
            'lunch_out': att.lunch_out.strftime('%H:%M:%S') if att.lunch_out else None,
            'status': att.status,
            'statuses': att.statuses,
            'date': att.date.strftime('%Y-%m-%d') if att.date else None,
            'hours_worked': float(att.hours_worked) if att.hours_worked else 0,
            'late_minutes': att.late_minutes or 0,
            'deduction_minutes': att.deduction_minutes or 0,
        }

    # If POST and AJAX, return JSON
    if request.method == 'POST' and _is_ajax():
        messages_list = []
        storage = messages.get_messages(request)
        for msg in storage:
            messages_list.append({'level': msg.level, 'message': str(msg)})
        
        # Determine success message
        if action == 'clock_in':
            success_msg = 'Clocked in successfully!'
        elif action == 'clock_out':
            success_msg = 'Clocked out successfully!'
        elif action == 'lunch_in':
            success_msg = 'Lunch break started!'
        elif action == 'lunch_out':
            success_msg = 'Lunch break ended!'
        else:
            success_msg = 'Action completed!'
        
        return JsonResponse({
            'success': True,
            'message': success_msg,
            'messages': messages_list,
            'attendance': _get_attendance_json(attendance),
            'clock_in_allowed': clock_in_allowed,
        })
    
    # If POST and HTMX, return HTML with HTMX headers for toast notifications
    if request.method == 'POST' and _is_htmx():
        messages_list = []
        storage = messages.get_messages(request)
        for msg in storage:
            messages_list.append({'level': msg.level, 'message': str(msg)})
        
        # Determine success message
        if action == 'clock_in':
            success_msg = 'Clocked in successfully!'
        elif action == 'clock_out':
            success_msg = 'Clocked out successfully!'
        elif action == 'lunch_in':
            success_msg = 'Lunch break started!'
        elif action == 'lunch_out':
            success_msg = 'Lunch break ended!'
        else:
            success_msg = 'Action completed!'
        
        # Build response with rendered template
        response = render(request, 'master/attendance/attendance_clock.html', _build_context())
        
        # Add HTMX headers for toast notifications
        if messages_list:
            # Trigger events for each message level
            for msg in messages_list:
                if msg['level'] == messages.SUCCESS:
                    response['HX-Trigger'] = f'htmx:successToast:{{"message": "{msg["message"]}", "type": "success"}}'
                elif msg['level'] == messages.ERROR:
                    response['HX-Trigger'] = f'htmx:errorToast:{{"message": "{msg["message"]}", "type": "error"}}'
                elif msg['level'] == messages.WARNING:
                    response['HX-Trigger'] = f'htmx:warningToast:{{"message": "{msg["message"]}", "type": "warning"}}'
                elif msg['level'] == messages.INFO:
                    response['HX-Trigger'] = f'htmx:infoToast:{{"message": "{msg["message"]}", "type": "info"}}'
        else:
            # No messages, add success trigger
            response['HX-Trigger'] = f'htmx:successToast:{{"message": "{success_msg}", "type": "success"}}'
        
        return response

    # ── Context ───────────────────────────────────────────────────────────────
    return render(request, 'master/attendance/attendance_clock.html', _build_context())


# ============================================
# PASSWORD RESET VIEWS
# ============================================

import random
import string
from django.views.decorators.http import require_POST, require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages


def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(characters) for _ in range(length))


@login_required
def password_reset_list(request):
    position_filter     = request.GET.get('position', '')
    role_filter         = request.GET.get('role', '')
    registration_filter = request.GET.get('registration', '')

    staff_list = Staff.objects.annotate(
        is_registered=Case(
            When(useraccount__isnull=False, then=Value(True)),
            default=Value(False),
            output_field=BooleanField()
        )
    ).select_related('useraccount', 'departmentlink', 'positionlink', 'role').order_by('last_name', 'first_name')

    if position_filter:
        staff_list = staff_list.filter(positionlink__id=position_filter)
    if role_filter:
        staff_list = staff_list.filter(role__id=role_filter)
    if registration_filter:
        if registration_filter == 'registered':
            staff_list = staff_list.filter(useraccount__isnull=False)
        elif registration_filter == 'not_registered':
            staff_list = staff_list.filter(useraccount__isnull=True)

    search_query = request.GET.get('search', '')
    if search_query:
        staff_list = staff_list.filter(
            Q(employee_number__icontains=search_query) |
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(email_address__icontains=search_query)
        )

    paginator   = Paginator(staff_list, 20)
    page_number = request.GET.get('page', 1)
    try:
        staff_page = paginator.page(page_number)
    except PageNotAnInteger:
        staff_page = paginator.page(1)
    except EmptyPage:
        staff_page = paginator.page(paginator.num_pages)

    positions = Position.objects.filter(is_active=True).order_by('position_name')
    roles     = Role.objects.filter(is_active=True).order_by('role_name')

    return render(request, 'master/password_reset_list.html', {
        'staff_list':           staff_page,
        'search_query':         search_query,
        'positions':            positions,
        'roles':                roles,
        'position_filter':      position_filter,
        'role_filter':          role_filter,
        'registration_filter':  registration_filter,
    })


@login_required
def password_reset_list_ajax(request):
    try:
        position_filter     = request.GET.get('position', '')
        role_filter         = request.GET.get('role', '')
        registration_filter = request.GET.get('registration', '')
        search_query        = request.GET.get('search', '')

        staff_list = Staff.objects.annotate(
            is_registered=Case(
                When(useraccount__isnull=False, then=Value(True)),
                default=Value(False),
                output_field=BooleanField()
            )
        ).select_related('useraccount', 'departmentlink', 'positionlink', 'role').order_by('last_name', 'first_name')

        if position_filter:
            staff_list = staff_list.filter(positionlink__id=position_filter)
        if role_filter:
            staff_list = staff_list.filter(role__id=role_filter)
        if registration_filter:
            if registration_filter == 'registered':
                staff_list = staff_list.filter(useraccount__isnull=False)
            elif registration_filter == 'not_registered':
                staff_list = staff_list.filter(useraccount__isnull=True)

        if search_query:
            staff_list = staff_list.filter(
                Q(employee_number__icontains=search_query) |
                Q(first_name__icontains=search_query) |
                Q(last_name__icontains=search_query) |
                Q(email_address__icontains=search_query)
            )

        staff_list = staff_list[:50]

        staff_data = []
        for staff in staff_list:
            has_account = hasattr(staff, 'useraccount') and staff.useraccount is not None
            staff_data.append({
                'id':              staff.id,
                'employee_number': staff.employee_number,
                'first_name':      staff.first_name,
                'last_name':       staff.last_name,
                'email_address':   staff.email_address,
                'department':      staff.departmentlink.department_name if staff.departmentlink else '--',
                'position':        staff.positionlink.position_name if staff.positionlink else '--',
                'role':            staff.role.role_name if staff.role else '--',
                'is_registered':   has_account,
                'last_login':      staff.useraccount.last_login.strftime('%b d, %Y %H:%M')
                                   if has_account and staff.useraccount.last_login else '--',
            })

        return JsonResponse({'staff': staff_data, 'count': len(staff_data)})

    except Exception as e:
        import traceback
        return JsonResponse({'error': str(e), 'trace': traceback.format_exc()}, status=500)


@require_POST
@login_required
def password_reset_confirm(request, staff_id):
    try:
        staff = get_object_or_404(Staff, id=staff_id)

        try:
            user_account = UserAccount.objects.get(employee=staff)
        except UserAccount.DoesNotExist:
            return JsonResponse({
                'success': False,
                'message': 'This employee has not registered yet. Cannot reset password.'
            }, status=400)

        new_password = generate_random_password(12)
        user_account.set_password(new_password)
        user_account.save()

        return JsonResponse({
            'success':         True,
            'message':         f'Password reset successfully for {staff.first_name} {staff.last_name}',
            'new_password':    new_password,
            'employee_name':   f'{staff.first_name} {staff.last_name}',
            'employee_number': staff.employee_number,
        })

    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)}, status=400)


@login_required
def password_reset_custom(request, staff_id):
    try:
        staff = get_object_or_404(Staff, id=staff_id)

        try:
            user_account = UserAccount.objects.get(employee=staff)
        except UserAccount.DoesNotExist:
            messages.error(
                request,
                f'{staff.first_name} {staff.last_name} has not registered yet. Cannot reset password.'
            )
            return redirect('master_dashboard:password_reset_list')

        if request.method == 'POST':
            new_password     = request.POST.get('new_password', '')
            confirm_password = request.POST.get('confirm_password', '')

            if not new_password:
                messages.error(request, 'Please enter a new password.')
                return redirect('master_dashboard:password_reset_list')

            if len(new_password) < 8:
                messages.error(request, 'Password must be at least 8 characters long.')
                return redirect('master_dashboard:password_reset_list')

            if new_password != confirm_password:
                messages.error(request, 'Passwords do not match.')
                return redirect('master_dashboard:password_reset_list')

            user_account.set_password(new_password)
            user_account.save()
            messages.success(
                request,
                f'Password for {staff.first_name} {staff.last_name} has been reset successfully.'
            )
        else:
            return redirect('master_dashboard:password_reset_list')

    except Exception as e:
        messages.error(request, f'Error resetting password: {str(e)}')

    return redirect('master_dashboard:password_reset_list')


# ============================================
# ROLE MANAGEMENT - MASTER DASHBOARD
# ============================================
from App.users.models import Role
from App.users.forms import RoleForm

@login_required
def role_list_master(request):
    emp      = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    emp_num  = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        if role_name not in ['Owner', 'Master', 'Developer', 'Admin'] and not is_owner:
            messages.error(request, "You don't have permission to view role management.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        messages.error(request, "You don't have permission to view role management.")
        return redirect('master_dashboard:master_dashboard')
    roles = Role.objects.all().order_by('role_name')
    return render(request, 'master/role_list.html', {'roles': roles, 'employee': emp, 'is_owner': is_owner})

@login_required
def role_add_master(request):
    emp      = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    emp_num  = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        if role_name not in ['Owner', 'Master', 'Developer', 'Admin'] and not is_owner:
            messages.error(request, "You don't have permission to add roles.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        messages.error(request, "You don't have permission to add roles.")
        return redirect('master_dashboard:master_dashboard')
    if request.method == 'POST':
        form = RoleForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Role added successfully.')
            return redirect('master_dashboard:role_list')
    else:
        form = RoleForm()
    return render(request, 'master/role_form.html', {'form': form, 'action': 'Add', 'employee': emp, 'is_owner': is_owner})

@login_required
def role_edit_master(request, pk):
    emp      = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    emp_num  = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        if role_name not in ['Owner', 'Master', 'Developer', 'Admin'] and not is_owner:
            messages.error(request, "You don't have permission to edit roles.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        messages.error(request, "You don't have permission to edit roles.")
        return redirect('master_dashboard:master_dashboard')
    role = get_object_or_404(Role, pk=pk)
    if request.method == 'POST':
        form = RoleForm(request.POST, instance=role)
        if form.is_valid():
            form.save()
            messages.success(request, 'Role updated successfully.')
            return redirect('master_dashboard:role_list')
    else:
        form = RoleForm(instance=role)
    return render(request, 'master/role_form.html', {'form': form, 'action': 'Edit', 'employee': emp, 'is_owner': is_owner, 'role': role})

@login_required
def role_delete_master(request, pk):
    emp      = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    emp_num  = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        if role_name not in ['Owner', 'Master', 'Developer', 'Admin'] and not is_owner:
            messages.error(request, "You don't have permission to delete roles.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        messages.error(request, "You don't have permission to delete roles.")
        return redirect('master_dashboard:master_dashboard')
    role = get_object_or_404(Role, pk=pk)
    if request.method == 'POST':
        role.delete()
        messages.success(request, 'Role deleted successfully.')
        return redirect('master_dashboard:role_list')
    return render(request, 'master/role_confirm_delete.html', {'role': role, 'employee': emp, 'is_owner': is_owner})


# ============================================
# POSITION MANAGEMENT - MASTER DASHBOARD
# ============================================
from App.users.models import Position
from App.users.forms import PositionForm

@login_required
def position_list_master(request):
    emp      = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    emp_num  = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        if role_name not in ['Owner', 'Master', 'Developer', 'Admin'] and not is_owner:
            messages.error(request, "You don't have permission to view position management.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        messages.error(request, "You don't have permission to view position management.")
        return redirect('master_dashboard:master_dashboard')
    positions = Position.objects.all().order_by('position_name')
    return render(request, 'master/position_list.html', {'positions': positions, 'employee': emp, 'is_owner': is_owner})

@login_required
def position_add_master(request):
    emp      = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    emp_num  = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        if role_name not in ['Owner', 'Master', 'Developer', 'Admin'] and not is_owner:
            messages.error(request, "You don't have permission to add positions.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        messages.error(request, "You don't have permission to add positions.")
        return redirect('master_dashboard:master_dashboard')
    if request.method == 'POST':
        form = PositionForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Position added successfully.')
            return redirect('master_dashboard:position_list')
    else:
        form = PositionForm()
    return render(request, 'master/position_form.html', {'form': form, 'action': 'Add', 'employee': emp, 'is_owner': is_owner})

@login_required
def position_edit_master(request, pk):
    emp      = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    emp_num  = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        if role_name not in ['Owner', 'Master', 'Developer', 'Admin'] and not is_owner:
            messages.error(request, "You don't have permission to edit positions.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        messages.error(request, "You don't have permission to edit positions.")
        return redirect('master_dashboard:master_dashboard')
    position = get_object_or_404(Position, pk=pk)
    if request.method == 'POST':
        form = PositionForm(request.POST, instance=position)
        if form.is_valid():
            form.save()
            messages.success(request, 'Position updated successfully.')
            return redirect('master_dashboard:position_list')
    else:
        form = PositionForm(instance=position)
    return render(request, 'master/position_form.html', {'form': form, 'action': 'Edit', 'employee': emp, 'is_owner': is_owner, 'position': position})

@login_required
def position_delete_master(request, pk):
    emp      = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    emp_num  = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        if role_name not in ['Owner', 'Master', 'Developer', 'Admin'] and not is_owner:
            messages.error(request, "You don't have permission to delete positions.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        messages.error(request, "You don't have permission to delete positions.")
        return redirect('master_dashboard:master_dashboard')
    position = get_object_or_404(Position, pk=pk)
    if request.method == 'POST':
        position.delete()
        messages.success(request, 'Position deleted successfully.')
        return redirect('master_dashboard:position_list')
    return render(request, 'master/position_confirm_delete.html', {'position': position, 'employee': emp, 'is_owner': is_owner})


# ============================================
# DEPARTMENT MANAGEMENT - MASTER DASHBOARD
# ============================================
from App.users.models import Department
from App.users.forms import DepartmentForm

@login_required
def department_list_master(request):
    emp      = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    emp_num  = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        if role_name not in ['Owner', 'Master', 'Developer', 'Admin'] and not is_owner:
            messages.error(request, "You don't have permission to view department management.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        messages.error(request, "You don't have permission to view department management.")
        return redirect('master_dashboard:master_dashboard')
    departments = Department.objects.all().order_by('department_name')
    return render(request, 'master/department_list.html', {'departments': departments, 'employee': emp, 'is_owner': is_owner})

@login_required
def department_add_master(request):
    emp      = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    emp_num  = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        if role_name not in ['Owner', 'Master', 'Developer', 'Admin'] and not is_owner:
            messages.error(request, "You don't have permission to add departments.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        messages.error(request, "You don't have permission to add departments.")
        return redirect('master_dashboard:master_dashboard')
    if request.method == 'POST':
        form = DepartmentForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Department added successfully.')
            return redirect('master_dashboard:department_list')
    else:
        form = DepartmentForm()
    return render(request, 'master/department_form.html', {'form': form, 'action': 'Add', 'employee': emp, 'is_owner': is_owner})

@login_required
def department_edit_master(request, pk):
    emp      = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    emp_num  = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        if role_name not in ['Owner', 'Master', 'Developer', 'Admin'] and not is_owner:
            messages.error(request, "You don't have permission to edit departments.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        messages.error(request, "You don't have permission to edit departments.")
        return redirect('master_dashboard:master_dashboard')
    department = get_object_or_404(Department, pk=pk)
    if request.method == 'POST':
        form = DepartmentForm(request.POST, instance=department)
        if form.is_valid():
            form.save()
            messages.success(request, 'Department updated successfully.')
            return redirect('master_dashboard:department_list')
    else:
        form = DepartmentForm(instance=department)
    return render(request, 'master/department_form.html', {'form': form, 'action': 'Edit', 'employee': emp, 'is_owner': is_owner, 'department': department})

@login_required
def department_delete_master(request, pk):
    emp      = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    emp_num  = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        if role_name not in ['Owner', 'Master', 'Developer', 'Admin'] and not is_owner:
            messages.error(request, "You don't have permission to delete departments.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        messages.error(request, "You don't have permission to delete departments.")
        return redirect('master_dashboard:master_dashboard')
    department = get_object_or_404(Department, pk=pk)
    if request.method == 'POST':
        department.delete()
        messages.success(request, 'Department deleted successfully.')
        return redirect('master_dashboard:department_list')
    return render(request, 'master/department_confirm_delete.html', {'department': department, 'employee': emp, 'is_owner': is_owner})


# ============================================
# RANK MANAGEMENT - MASTER DASHBOARD
# ============================================
@login_required
def rank_list_master(request):
    emp      = get_current_employee(request)
    is_owner = request.session.get('is_owner', False)
    emp_num  = request.session.get('employee_number')
    if emp_num and emp:
        role_name = emp.role.role_name if emp.role else ''
        if role_name not in ['Owner', 'Master', 'Developer', 'Admin'] and not is_owner:
            messages.error(request, "You don't have permission to view rank management.")
            return redirect('master_dashboard:master_dashboard')
    elif not is_owner:
        messages.error(request, "You don't have permission to view rank management.")
        return redirect('master_dashboard:master_dashboard')

    staff_list   = Staff.objects.select_related('role').filter(
        rank__isnull=False
    ).exclude(rank='').order_by('rank', 'last_name')
    rank_choices = Staff.RANK_CHOICES
    rank_counts  = {}
    for rank_value, rank_label in rank_choices:
        safe_key = rank_value.replace('-', '_')
        rank_counts[safe_key]   = staff_list.filter(rank=rank_value).count()
        rank_counts[rank_value] = rank_counts[safe_key]

    return render(request, "master/rank_list.html", {
        "employee":     emp,
        "is_owner":     is_owner,
        'staff_list':   staff_list,
        'rank_choices': rank_choices,
        'rank_counts':  rank_counts,
    })


@login_required
def rank_add_master(request):
    messages.info(request, "Rank is a predefined choice field. Please edit staff members to change their rank.")
    return redirect('master_dashboard:rank_list')


@login_required
def rank_edit_master(request, pk):
    from django.urls import reverse
    return redirect(reverse('master_dashboard:master_user_edit', args=[pk]))


@login_required
def rank_delete_master(request, pk):
    messages.info(request, "Rank cannot be deleted as it is a predefined choice field.")
    return redirect('master_dashboard:rank_list')


# ============================================
# AJAX: Get Absent Records (Master Dashboard)
# ============================================
@login_required
def get_absent_records_ajax_master(request):
    from App.human_resource.models import Attendance

    emp_num = request.session.get('employee_number')
    if not emp_num:
        return JsonResponse({'error': 'Not authenticated'}, status=401)

    try:
        employee = Staff.objects.get(employee_number=emp_num)
    except Staff.DoesNotExist:
        return JsonResponse({'error': 'Employee not found'}, status=404)

    absent_records = Attendance.objects.filter(
        employee=employee,
        status='absent',
    ).order_by('-date')

    data = []
    for record in absent_records:
        note        = record.note or ''
        is_appealed = 'Appealed' in note or 'HR Review' in note
        data.append({
            'id':           record.id,
            'date':         record.date.strftime('%Y-%m-%d') if record.date else None,
            'date_display': record.date.strftime('%B %d, %Y') if record.date else None,
            'note':         record.note,
            'is_appealed':  is_appealed,
        })

    return JsonResponse({'absent_records': data})


# ============================================
# Employee: Appeal Auto-Marked Absent (Master)
# ============================================
@require_http_methods(["POST"])
@login_required
def appeal_absent_master(request, pk):
    from App.human_resource.models import Attendance
    from django.http import JsonResponse

    emp_num = request.session.get('employee_number')
    if not emp_num:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': False, 'message': 'Please log in again.'})
        return redirect('login')

    employee = Staff.objects.filter(employee_number=emp_num).first()
    if not employee:
        messages.error(request, "Your account could not be found. Please log in again.")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': False, 'message': 'Your account could not be found. Please log in again.'})
        return redirect('login')

    attendance = get_object_or_404(Attendance, pk=pk, employee=employee)

    if attendance.status != 'absent':
        messages.error(request, "Only absent records can be appealed.")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': False, 'message': 'Only absent records can be appealed.'})
        return redirect('master_dashboard:attendance_clock_master')

    if attendance.note and '[Appealed]' in attendance.note:
        messages.error(request, "This absent record has already been appealed.")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': False, 'message': 'This absent record has already been appealed.'})
        return redirect('master_dashboard:attendance_clock_master')

    appeal_reason = request.POST.get('appeal_reason', '').strip()
    action_type   = request.POST.get('action_type', 'appeal')

    if not appeal_reason:
        messages.error(request, "Please provide a reason for your appeal.")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': False, 'message': 'Please provide a reason for your appeal.'})
        return redirect('master_dashboard:attendance_clock_master')

    if action_type == 'request_hr':
        attendance.note = f"[HR Review Requested - Absent Appeal] {appeal_reason}"
        messages.success(request, "Your appeal has been submitted to HR for review.")
        success_msg = "Your appeal has been submitted to HR for review."
    else:
        attendance.note = f"[Appealed] {appeal_reason}"
        messages.success(request, "Your appeal has been recorded. Please contact HR for further assistance.")
        success_msg = "Your appeal has been recorded. Please contact HR for further assistance."

    attendance.save()
    
    # Return JSON for AJAX requests
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'success': True, 'message': success_msg})
    
    return redirect('master_dashboard:attendance_clock_master')
