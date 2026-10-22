# Production-equivalent station web application: separate storage identity.
# Requires published immutable Python/front-end software and rootfs. The
# operator must select verified software_view before any real deployment.
application(
    name="station-access",
    description="Station portal; web only, no host mirror credentials",
    persistent=True,
    # Administrator-provisioned, controller-bound stable non-root identity.
    execution_identity="application",
    multiple_instances=False,
    start_policy="externally-controlled",
    writable_mounts=("station-data",),
    preparation_revision="production-station-data-v1",
    preparation=(program(
        name="prepare",
        command=("/usr/bin/true",),
        execution_timeout_seconds=60,
        mounts={"station-data": "/var/lib/station-access"},
    ),),
    programs=(program(
        name="web",
        command=("/usr/bin/python3", "-m", "zog.station_access.cli",
                 "--host", "127.0.0.1", "--port", "8000",
                 "--state-directory", "/var/lib/station-access"),
        mounts={"station-data": "/var/lib/station-access"},
        environment={
            "DJANGO_SETTINGS_MODULE": "zog.station_access.project.settings",
            "STATION_ACCESS_STATE_DIRECTORY": "/var/lib/station-access",
            "STATION_ACCESS_DEBUG": "0",
            "STATION_ACCESS_ALLOWED_HOSTS": "localhost,127.0.0.1",
            # ARCHIVE_MIRROR_CONFIGURATION deliberately absent: the provider
            # owns another application and standalone catalogue database.
        },
    ),),
)
