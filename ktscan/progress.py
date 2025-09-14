from typing import Optional

from rich.console import Console
from rich.progress import (
    Progress,
    TaskID,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    MofNCompleteColumn,
    TimeElapsedColumn,
)


class ThreeStageProgress:
    """Manages three-stage progress display for certificate scanning"""

    def __init__(self, console: Console, show_progress: bool = True):
        self.console = console
        self.show_progress = show_progress
        self.progress: Optional[Progress] = None

        # Task IDs for each stage
        self.stage1_task: Optional[TaskID] = None
        self.stage2_task: Optional[TaskID] = None
        self.stage3_task: Optional[TaskID] = None

    def __enter__(self):
        if not self.show_progress:
            return self

        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}", justify="left"),
            BarColumn(bar_width=40),  # Fixed width bar
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console,
            expand=False,
        )
        self.progress.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.progress:
            self.progress.__exit__(exc_type, exc_val, exc_tb)

    def start_stage1(self, total_targets: int):
        """Start Stage 1: Identifying Targets"""
        if not self.progress:
            return

        self.stage1_task = self.progress.add_task(
            "Identifying Targets...", total=total_targets
        )

        # Add placeholder tasks for future stages
        self.stage2_task = self.progress.add_task(
            "Downloading Certificates...", total=1, visible=False
        )
        self.stage3_task = self.progress.add_task(
            "Validating Certificates...", total=1, visible=False
        )

    def update_stage1(self, completed: int):
        """Update Stage 1 progress"""
        if self.progress and self.stage1_task is not None:
            self.progress.update(self.stage1_task, completed=completed)

    def complete_stage1_start_stage2(self, total_endpoints: int):
        """Complete Stage 1 and start Stage 2"""
        if not self.progress:
            return

        # Complete stage 1
        if self.stage1_task is not None:
            self.progress.update(
                self.stage1_task, completed=self.progress.tasks[self.stage1_task].total
            )

        # Start stage 2
        if self.stage2_task is not None:
            self.progress.update(
                self.stage2_task, total=total_endpoints, completed=0, visible=True
            )

    def update_stage2(self, completed: int):
        """Update Stage 2 progress"""
        if self.progress and self.stage2_task is not None:
            self.progress.update(self.stage2_task, completed=completed)

    def complete_stage2_start_stage3(self, total_unique_certificates: int):
        """Complete Stage 2 and start Stage 3"""
        if not self.progress:
            return

        # Complete stage 2
        if self.stage2_task is not None:
            self.progress.update(
                self.stage2_task, completed=self.progress.tasks[self.stage2_task].total
            )

        # Start stage 3
        if self.stage3_task is not None:
            self.progress.update(
                self.stage3_task,
                total=total_unique_certificates,
                completed=0,
                visible=True,
            )

    def update_stage3(self, completed: int):
        """Update Stage 3 progress"""
        if self.progress and self.stage3_task is not None:
            self.progress.update(self.stage3_task, completed=completed)

    def complete_stage3(self):
        """Complete Stage 3"""
        if self.progress and self.stage3_task is not None:
            self.progress.update(
                self.stage3_task, completed=self.progress.tasks[self.stage3_task].total
            )
